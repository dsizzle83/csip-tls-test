package suitecsip

// ringdelta_test.go pins the arithmetic that decides "has the DUT polled since
// this check's baseline" against gridsim's BOUNDED request-log ring.
//
// The defect these lock down is subtle and it cost a nine-cycle soak. gridsim
// keeps 4000 log lines (sim/simapi/logs.go) and the harness reads the whole
// retained ring on every poll. One 2030.5 discovery walk is dozens of lines, and
// gridsim is not restarted between soak cycles, so within a couple of hours the
// ring is permanently saturated: it retains a CONSTANT number of /dcap lines
// while the DUT polls perfectly on time. Every predicate written as "more /dcap
// GETs than the baseline had" is then unsatisfiable forever, so the check waits
// out its entire window and reports that the DUT never polled — which is the
// signature the 2026-08-07 WAN/LAN split soak recorded 0-3 times per cycle,
// every cycle, always about a DUT that was polling fine.
//
// The fix is to compare SEQUENCE POSITIONS instead of totals. These tests cover
// the four positions two reads can be in, including the two that used to be
// unreachable-by-construction and the one that used to panic outright.

import (
	"fmt"
	"strings"
	"testing"
)

// walkLines renders n log lines in gridsim's format, alternating the discovery
// root with a resource fetch, so a "walk" in these fixtures looks like the
// mixed traffic a real one produces rather than a run of identical lines.
func walkLines(from, n int) []string {
	out := make([]string, 0, n)
	for i := from; i < from+n; i++ {
		path := "/edev/1"
		if i%4 == 0 {
			path = DiscoveryRoot
		}
		out = append(out, fmt.Sprintf("2026/08/07 12:00:00 [gridsim] GET %s (peer=69.0.0.2:5000) seq=%d", path, i))
	}
	return out
}

// countDcap is what the fixtures above imply, kept explicit so a test asserting
// "4 new /dcap" is not silently agreeing with a bug in its own helper.
func countDcap(lines []string) int {
	n := 0
	for _, ln := range lines {
		if strings.Contains(ln, "GET "+DiscoveryRoot+" ") {
			n++
		}
	}
	return n
}

// ringView builds a view as if the ring had been read at this position: lines
// numbered [firstSeq, firstSeq+n) with pid attached.
func ringView(firstSeq, n, pid int) ServerView {
	lines := walkLines(firstSeq, n)
	return ServerView{
		Available:   true,
		rawLines:    lines,
		rawFirstSeq: uint64(firstSeq),
		Requests:    parseRequestLog(lines),
		Status:      AdminStatus{PID: pid},
	}
}

// TestRingDeltaPositions is the whole arithmetic, as integers.
func TestRingDeltaPositions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		base    logPos
		cur     logPos
		wantLo  int
		wantR   logReach
		gapWord string
	}{
		{
			// The ordinary case: the ring has room, the baseline's end is still
			// inside it, and the new lines are the ones past that end.
			name: "unsaturated ring, baseline still inside it",
			base: logPos{firstSeq: 0, n: 10, pid: 42},
			cur:  logPos{firstSeq: 0, n: 25, pid: 42},
			// 10 lines existed at baseline; lines[10:] are the new ones.
			wantLo: 10, wantR: logExact,
		},
		{
			// (a) The baseline was taken when the ring was ALREADY FULL. This is
			// the case the old absolute-count predicates could not survive:
			// the retained /dcap total is constant, so a total-based test never
			// fires again. Sequence arithmetic does not care about saturation.
			name: "baseline taken against an already-saturated ring",
			base: logPos{firstSeq: 3000, n: 4000, pid: 42}, // ends at 7000
			cur:  logPos{firstSeq: 3500, n: 4000, pid: 42}, // ends at 7500
			// 500 lines arrived; they start 3500 into the current read.
			wantLo: 3500, wantR: logExact,
		},
		{
			// (b) The ring wrapped PAST the baseline during the wait. Everything
			// still retained is newer than the baseline (eviction only happens
			// on append), so counting all of it is sound — but some new lines
			// are gone, so a count under-reports and must say so.
			name:   "ring wrapped past the baseline during the wait",
			base:   logPos{firstSeq: 0, n: 4000, pid: 42},    // ends at 4000
			cur:    logPos{firstSeq: 5000, n: 4000, pid: 42}, // starts after that
			wantLo: 0, wantR: logPartial, gapWord: "evicted",
		},
		{
			// (c) The simulator restarted: sequence numbers reset to zero. One
			// process cannot go backwards, so this is not a delta at all. The
			// OLD code computed lo = 7000-0 = 7000 and sliced a 50-element
			// slice with it, which panicked.
			name:   "gridsim restarted mid-wait, sequence reset",
			base:   logPos{firstSeq: 3000, n: 4000, pid: 0}, // ends at 7000
			cur:    logPos{firstSeq: 0, n: 50, pid: 0},      // ends at 50
			wantLo: 0, wantR: logIncomparable, gapWord: "BACKWARDS",
		},
		{
			// A replacement process that had ALREADY logged more than the
			// original would sail past the sequence check, so the declared pid
			// is what catches it. This is certify's preflight "orphan-and-
			// replacement" shape, discovered mid-run instead of at startup.
			name:   "a different process is answering, sequence looks plausible",
			base:   logPos{firstSeq: 0, n: 10, pid: 111},
			cur:    logPos{firstSeq: 0, n: 9000, pid: 222},
			wantLo: 0, wantR: logIncomparable, gapWord: "changed process",
		},
		{
			name:   "the same process is not mistaken for a replacement",
			base:   logPos{firstSeq: 0, n: 10, pid: 111},
			cur:    logPos{firstSeq: 0, n: 40, pid: 111},
			wantLo: 10, wantR: logExact,
		},
		{
			// A gridsim predating the pid field reports 0. That must read as
			// "unknown", never as "a process whose id is 0 that differs from
			// 111" — otherwise every delta against an older sim is incomparable
			// and every wait predicate stops working.
			name:   "an unknown pid on one side falls back to the sequence",
			base:   logPos{firstSeq: 0, n: 10, pid: 0},
			cur:    logPos{firstSeq: 0, n: 40, pid: 111},
			wantLo: 10, wantR: logExact,
		},
		{
			name: "two empty reads are an empty, exact delta",
			base: logPos{}, cur: logPos{},
			wantLo: 0, wantR: logExact,
		},
		{
			// Exactly abutting: the baseline's end is the current read's first
			// line. Every retained line is new and the offset is zero — the
			// boundary between the exact and evicted branches.
			name:   "the read begins exactly where the baseline ended",
			base:   logPos{firstSeq: 0, n: 4000, pid: 42},
			cur:    logPos{firstSeq: 4000, n: 100, pid: 42},
			wantLo: 0, wantR: logExact,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo, reach, gap := ringDelta(tc.base, tc.cur)
			if lo != tc.wantLo {
				t.Errorf("lo = %d, want %d", lo, tc.wantLo)
			}
			if reach != tc.wantR {
				t.Errorf("reach = %d, want %d (gap: %q)", reach, tc.wantR, gap)
			}
			if (gap != "") != (tc.wantR != logExact) {
				t.Errorf("a non-exact delta must explain itself and an exact one must not: reach=%d gap=%q",
					reach, gap)
			}
			if tc.gapWord != "" && !strings.Contains(gap, tc.gapWord) {
				t.Errorf("the gap must say %q: %s", tc.gapWord, gap)
			}
			// The offset must always be a legal index into cur's lines, or the
			// caller's slice panics — which is precisely how the restart case
			// used to fail.
			if lo < 0 || lo > tc.cur.n {
				t.Errorf("lo = %d is not a legal index into a %d-line read", lo, tc.cur.n)
			}
		})
	}
}

// TestPolledSinceSurvivesRingSaturation is THE regression lock for the soak
// flap. Both reads retain the same number of /dcap lines — that is what
// saturation MEANS — while the sequence shows the DUT walked twice over. The
// old predicate compared those two equal totals and concluded the DUT had not
// polled.
func TestPolledSinceSurvivesRingSaturation(t *testing.T) {
	const ring = 4000
	base := ringView(10000, ring, 42) // ends at 14000
	cur := ringView(10240, ring, 42)  // 240 lines later, same retained size

	if got, want := base.GETs(DiscoveryRoot), cur.GETs(DiscoveryRoot); got != want {
		t.Fatalf("fixture is not saturated: base retains %d /dcap and cur retains %d — this test is "+
			"meaningless unless the TOTALS are equal", got, want)
	}
	// The old predicate, spelled out, so its failure is visible here rather
	// than only in a bench log nine cycles later.
	if cur.GETs(DiscoveryRoot) >= base.GETs(DiscoveryRoot)+1 {
		t.Fatal("fixture error: the pre-fix absolute-count predicate should be UNSATISFIABLE here")
	}

	n, reach := cur.GETsSince(base, DiscoveryRoot)
	if reach != logExact {
		t.Errorf("reach = %d, want logExact: nothing was evicted past the baseline here", reach)
	}
	if want := countDcap(walkLines(14000, 240)); n != want {
		t.Errorf("new /dcap GETs = %d, want %d", n, want)
	}
	if !cur.PolledSince(base, DiscoveryRoot, 1) {
		t.Fatal("the DUT walked twice over a saturated ring and PolledSince still reports it did not " +
			"poll — this is the exact defect the 2026-08-07 soak reported as 0-3 DUT failures per cycle")
	}
}

// A DUT that genuinely has not polled must still read as not having polled. The
// fix must not make the predicate true-by-default, which would convert every
// real "the DUT never polled" finding into a silent pass.
func TestPolledSinceStillFalseWhenTheDUTIsSilent(t *testing.T) {
	base := ringView(10000, 4000, 42)
	// The same read again: nothing arrived at all.
	cur := ringView(10000, 4000, 42)

	if n, _ := cur.GETsSince(base, DiscoveryRoot); n != 0 {
		t.Errorf("new /dcap GETs = %d, want 0", n)
	}
	if cur.PolledSince(base, DiscoveryRoot, 1) {
		t.Fatal("an idle window must not satisfy PolledSince")
	}

	// And lines that are new but contain no discovery-root GET must not count
	// as a walk either.
	quiet := ServerView{
		Available:   true,
		rawLines:    []string{"2026/08/07 12:00:00 [gridsim] PUT /edev/1/der/1/ders (peer=69.0.0.2:5000)"},
		rawFirstSeq: 14000,
		Status:      AdminStatus{PID: 42},
	}
	if quiet.PolledSince(base, DiscoveryRoot, 1) {
		t.Error("a window containing a PUT but no /dcap GET is not a discovery walk")
	}
}

// (b) again, at the ServerView level: a wrap during the wait still proves the
// DUT polled, because everything retained is newer than the baseline. Refusing
// to be satisfied here would be the false-FAIL bug in its other direction.
func TestPolledSinceIsSatisfiableAcrossAWrap(t *testing.T) {
	base := ringView(0, 4000, 42)   // ends at 4000
	cur := ringView(5000, 4000, 42) // began after the baseline's end

	n, reach := cur.GETsSince(base, DiscoveryRoot)
	if reach != logPartial {
		t.Errorf("reach = %d, want logPartial: lines were evicted past the baseline", reach)
	}
	if n == 0 {
		t.Fatal("every retained line is newer than the baseline, so the /dcap among them must be counted")
	}
	if !cur.PolledSince(base, DiscoveryRoot, 1) {
		t.Fatal("a wrap loses lines but proves activity: the predicate must still be satisfiable")
	}
	// The window must still be MARKED as incomplete for the criteria.
	if gap := cur.Since(base).RequestLogGap; gap == "" {
		t.Error("a wrap must still set RequestLogGap so a criterion cannot grade a thin window as a DUT fault")
	}
}

// (c) The restart case, end to end: no panic, and — because the check's Setup
// published its DERControl to a server that is now gone — no claim that the DUT
// polled for it either.
func TestRestartIsNeitherAPanicNorAPoll(t *testing.T) {
	base := ringView(3000, 4000, 111) // ends at 7000
	fresh := ringView(0, 50, 222)     // a brand-new process, busy already

	// The pre-fix code sliced fresh.rawLines[7000:] here and panicked.
	d := fresh.Since(base)
	if d.RequestLogGap == "" {
		t.Fatal("a simulator restart must set RequestLogGap")
	}
	if len(d.Requests) != 0 {
		t.Errorf("a restarted simulator's log cannot be dated to this check's baseline, so it must not be "+
			"handed back as this window's requests; got %d", len(d.Requests))
	}
	if n, reach := fresh.GETsSince(base, DiscoveryRoot); n != 0 || reach != logIncomparable {
		t.Errorf("GETsSince = (%d, %d), want (0, logIncomparable)", n, reach)
	}
	if fresh.PolledSince(base, DiscoveryRoot, 1) {
		t.Fatal("a restarted gridsim has lost whatever this check published, so its traffic must not " +
			"close the window as though the DUT had polled for it")
	}

	// The same, detected from the sequence alone on a gridsim too old to report
	// a pid — the reset is still unmistakable.
	oldBase := ringView(3000, 4000, 0)
	oldFresh := ringView(0, 50, 0)
	if oldFresh.PolledSince(oldBase, DiscoveryRoot, 1) {
		t.Error("a sequence that went backwards is a restart even when no pid is published")
	}
}

// The synthetic path — views whose Requests were set directly, with no ring
// behind them — must keep working exactly as before, because most of this
// suite's predicate tests are written that way.
func TestPolledSinceOnFixtureViewsWithNoRing(t *testing.T) {
	req := func(path string) ServerRequest { return ServerRequest{Method: "GET", Path: path} }

	base := ServerView{Requests: []ServerRequest{req(DiscoveryRoot)}}
	same := ServerView{Requests: []ServerRequest{req(DiscoveryRoot)}}
	walked := ServerView{Requests: []ServerRequest{req(DiscoveryRoot), req(DiscoveryRoot)}}

	if same.PolledSince(base, DiscoveryRoot, 1) {
		t.Error("no new fixture requests must not read as a poll")
	}
	if !walked.PolledSince(base, DiscoveryRoot, 1) {
		t.Error("one appended /dcap in a fixture view must read as a poll")
	}
	// ERR-001 wants TWO (the redirected GET and the follow).
	if walked.PolledSince(base, DiscoveryRoot, 2) {
		t.Error("one new /dcap must not satisfy a want of two")
	}
	twice := ServerView{Requests: []ServerRequest{
		req(DiscoveryRoot), req(DiscoveryRoot), req(DiscoveryRoot),
	}}
	if !twice.PolledSince(base, DiscoveryRoot, 2) {
		t.Error("two new /dcap must satisfy ERR-001's want of two")
	}
}

// The no-cursor fallback (an older simulator serving only the SSE stream) is
// still allowed to satisfy the predicate — it is a length delta and can only
// under-report — but it must be marked partial so nothing grades a zero from it
// as a fact about the DUT.
func TestPolledSinceUnderTheApproximateFallback(t *testing.T) {
	lines := walkLines(0, 8)
	base := ServerView{rawLines: lines[:4], Requests: parseRequestLog(lines[:4]), logApproximate: true}
	cur := ServerView{
		Available: true, rawLines: lines, Requests: parseRequestLog(lines), logApproximate: true,
	}

	n, reach := cur.GETsSince(base, DiscoveryRoot)
	if reach != logPartial {
		t.Errorf("reach = %d, want logPartial for a cursorless read", reach)
	}
	if n == 0 {
		t.Error("the length delta still sees the appended lines")
	}
	if !cur.PolledSince(base, DiscoveryRoot, 1) {
		t.Error("an approximate delta may under-report but must still be satisfiable")
	}
}
