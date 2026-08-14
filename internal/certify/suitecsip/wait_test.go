package suitecsip

// wait_test.go pins the derivation of the poll-cycle window — the number that
// decides whether "gridsim's request log records no GET /dcap from the DUT in
// this window" is a finding about the DUT or a finding about the harness.
//
// It was the latter for nine soak cycles. The 2026-08-07 WAN/LAN split soak
// (runs/ethsplit-20260807/soak/cycle*) ran the CSIP leg nine times against a
// gridsim launched with -poll-rate-s 60 and a fixed 90 s wait, and every cycle
// reported 0-3 FAILs — a DIFFERENT handful of BASIC event rows each time,
// always with that same signature. 90 s against a 60 s advertisement is 1.5
// periods: whether a given row passed came down to where the run happened to
// start relative to the DUT's own poll boundary, which is not a property of the
// DUT. These tests exist so that never silently comes back.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"csip-tls-test/internal/certify"
)

// benchAdvertisedPollRate is what scripts/bench-sims-up.sh launches gridsim
// with (-poll-rate-s 60). It is named because the point of most of these tests
// is what the derivation does at THIS number.
const benchAdvertisedPollRate = 60

// waitTestCtx builds a run context for the derivation: a gridsim advertising
// pollRateS (0 = a server that reports no poll_rate_s at all), a DUT config
// serving floorJSON (empty = no -gateway-ssh, so the floor is unreadable), and
// the given -param set.
func waitTestCtx(t *testing.T, pollRateS int, floorJSON string, params map[string]string) *certify.RunCtx {
	t.Helper()
	rc := &certify.RunCtx{
		Case:   &certify.Case{UID: "csip-conf-v1.3::BASIC-011"},
		Params: params,
	}
	if pollRateS >= 0 {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/status" {
				http.NotFound(w, r)
				return
			}
			body := map[string]any{"programs": []any{}, "server_time": 1}
			if pollRateS > 0 {
				body["poll_rate_s"] = pollRateS
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}))
		t.Cleanup(srv.Close)
		rc.GridSim = certify.NewAdminClient(srv.URL, srv.Client())
		rc.Targets = certify.Targets{GridSimAdmin: srv.URL}
	}
	if floorJSON != "" {
		rc.Gateway = &certify.Gateway{
			SSH: "test",
			Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[len(args)-1] != dutNorthboundConfig {
					return nil, errNoSuchDUTFile
				}
				return []byte(floorJSON), nil
			},
		}
	}
	return rc
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNoSuchDUTFile = constErr("cat: can't open: No such file or directory")

// TestFetchWaitAtTheBenchAdvertisedRateBeatsTheOldConstant is the regression
// lock for the soak flap. At the rate the bench actually advertises, the
// derived window must be a real multiple of the cadence — comfortably more
// than the 1.5 periods the old fixed 90 s bought.
func TestFetchWaitAtTheBenchAdvertisedRateBeatsTheOldConstant(t *testing.T) {
	rc := waitTestCtx(t, benchAdvertisedPollRate, "", nil)

	got, why := fetchWait(context.Background(), rc, spec{})

	if want := 150 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s (%d x the advertised %ds pollRate plus %s of slack)",
			got, want, waitPeriods, benchAdvertisedPollRate, waitSlack)
	}
	if got <= defaultWait {
		t.Fatalf("the derived wait %s is no wider than the fixed %s it replaces, so the flap this change "+
			"exists to close would survive it", got, defaultWait)
	}
	for _, want := range []string{"pollRate", "poll_rate_s", "1m0s"} {
		if !strings.Contains(why, want) {
			t.Errorf("the explanation must name the source the window was derived from (%q missing): %s",
				want, why)
		}
	}
}

// The DUT honours the server's rate but never polls faster than its own
// configured floor, so a floor SLOWER than the advertisement is the cadence the
// window has to span. This is the case the bench's -poll-rate-s 60 convention
// hides: read the advertisement alone and the window is 150 s for a DUT that
// only walks every 120.
func TestFetchWaitTakesTheSlowerOfTheAdvertisedRateAndTheDUTFloor(t *testing.T) {
	rc := waitTestCtx(t, benchAdvertisedPollRate, `{"discovery_interval_s":120}`, nil)

	got, why := fetchWait(context.Background(), rc, spec{})

	if want := 270 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s (%d x the 120 s floor plus %s: the floor is the slower of the two)",
			got, want, waitPeriods, waitSlack)
	}
	if !strings.Contains(why, dutDiscoveryField) {
		t.Errorf("the explanation must name the floor that governed: %s", why)
	}
}

// An unreadable cadence must fall back to the old constant and SAY it fell
// back. Silently agreeing with the fallback would put the pre-fix window back
// in the bundle with a post-fix sentence attached to it.
func TestFetchWaitFallsBackWhenNoCadenceCanBeRead(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pollRateS int
	}{
		{"no gridsim admin API configured", -1},
		{"a gridsim that reports no poll_rate_s", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := waitTestCtx(t, tc.pollRateS, "", nil)

			got, why := fetchWait(context.Background(), rc, spec{})

			if got != defaultWait {
				t.Fatalf("wait = %s, want the %s fallback", got, defaultWait)
			}
			if !strings.Contains(why, "fallback") {
				t.Errorf("the explanation must say the window is a fallback and not derived from any "+
					"cadence the DUT keeps: %s", why)
			}
		})
	}
}

// IEEE 2030.5 §10.2.3 lets a server advertise 900 s. Deriving straight from
// that is half an hour per row, which is not a suite run — so the cap bites and
// the explanation hands the reader the lever that overrides it.
func TestFetchWaitCapsARunawayAdvertisement(t *testing.T) {
	rc := waitTestCtx(t, 900, "", nil)

	got, why := fetchWait(context.Background(), rc, spec{})

	if got != waitCap {
		t.Fatalf("wait = %s, want the %s cap (2 x 900 s + slack would be %s)",
			got, waitCap, 2*900*time.Second+waitSlack)
	}
	if !strings.Contains(why, "bound") {
		t.Errorf("the explanation must say the bound, not the cadence, chose this window: %s", why)
	}
}

// The floor holds in the other direction: a very fast bench must not shrink the
// window below what the suite was already giving every row.
func TestFetchWaitNeverGoesBelowTheOldConstant(t *testing.T) {
	rc := waitTestCtx(t, 5, "", nil)

	got, _ := fetchWait(context.Background(), rc, spec{})

	if got != defaultWait {
		t.Fatalf("wait = %s, want the %s floor (2 x 5 s + slack is well under it)", got, defaultWait)
	}
}

// The operator override is the whole contract for the long-window rows:
// BASIC-029, CORE-022 and CORE-023 are run as separate invocations carrying
// their own -param csip.wait precisely so they can buy a window the suite would
// never default to. It must arrive at run() exactly as typed — not floored, not
// capped, and NOT trimmed to fit a deadline, even a deadline it plainly does
// not fit inside.
func TestExplicitParamWinsVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
		want time.Duration
	}{
		{"the campaign's long-window value", "12m", 12 * time.Minute},
		{"a value above the cap", "8m", 8 * time.Minute},
		{"a value below the floor", "20s", 20 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A gridsim advertising 60 s AND a deadline far too short for the
			// requested wait: both of the things that move a derived value.
			rc := waitTestCtx(t, benchAdvertisedPollRate, `{"discovery_interval_s":60}`,
				map[string]string{waitParam: tc.val})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			got, why := fetchWait(ctx, rc, spec{Change: func(context.Context, *Driver, map[string]string) error {
				return nil
			}, ChangeWait: changeWaitFullCycle})

			if got != tc.want {
				t.Fatalf("wait = %s, want the operator's %s used verbatim", got, tc.want)
			}
			if !strings.Contains(why, waitParam) {
				t.Errorf("the explanation must record that an operator set this: %s", why)
			}
		})
	}
}

// A -param that does not parse is a typo, and a typo must not silently buy the
// operator a window they did not ask for. It is ignored and the derivation
// runs, which is what the pre-fix code did too.
func TestUnparseableParamFallsThroughToTheDerivation(t *testing.T) {
	for _, val := range []string{"twelve minutes", "12", "-5m", "0s"} {
		t.Run(val, func(t *testing.T) {
			rc := waitTestCtx(t, benchAdvertisedPollRate, "", map[string]string{waitParam: val})

			got, why := fetchWait(context.Background(), rc, spec{})

			if want := 150 * time.Second; got != want {
				t.Fatalf("wait = %s, want the derived %s: an unusable -param must be ignored, not honoured",
					got, want)
			}
			if strings.Contains(why, "set explicitly") {
				t.Errorf("the explanation must not claim an operator set this window: %s", why)
			}
		})
	}
}

// A spec that names its own Wait keeps it. No row does today, but the field is
// part of spec's contract and a derivation that quietly overrode it would be a
// trap for the first row that needs one.
func TestSpecOwnWaitIsNotDerivedOver(t *testing.T) {
	rc := waitTestCtx(t, benchAdvertisedPollRate, "", nil)

	got, why := fetchWait(context.Background(), rc, spec{Wait: 7 * time.Minute})

	if want := 7 * time.Minute; got != want {
		t.Fatalf("wait = %s, want the spec's own %s", got, want)
	}
	if !strings.Contains(why, "spec") {
		t.Errorf("the explanation must say the row fixed this itself: %s", why)
	}
}

// TestFitWaitToBudget is the arithmetic that keeps a widened window from
// turning a check that used to produce criteria into a check killed by
// -timeout, which produces none.
func TestFitWaitToBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wait      time.Duration
		remaining time.Duration
		overhead  time.Duration
		slots     int
		want      time.Duration
		trimmed   bool
	}{
		{
			name: "no deadline at all leaves the derivation alone",
			wait: 5 * time.Minute, remaining: 0, overhead: waitBudgetReserve, slots: 1,
			want: 5 * time.Minute,
		},
		{
			name: "one slot inside the campaign's 5m -timeout is affordable",
			wait: 150 * time.Second, remaining: 5 * time.Minute, overhead: waitBudgetReserve, slots: 1,
			want: 150 * time.Second,
		},
		{
			name: "two full cycles sharing a 5m -timeout must be trimmed",
			wait: 150 * time.Second, remaining: 5 * time.Minute, overhead: waitBudgetReserve, slots: 2,
			want: 127500 * time.Millisecond, trimmed: true,
		},
		{
			name: "a trim never goes below the constant it replaced",
			wait: 150 * time.Second, remaining: 100 * time.Second, overhead: waitBudgetReserve, slots: 2,
			want: defaultWait, trimmed: true,
		},
		{
			name: "an already-expired budget still yields the old constant",
			wait: 5 * time.Minute, remaining: time.Second, overhead: waitBudgetReserve, slots: 2,
			want: defaultWait, trimmed: true,
		},
		{
			name: "a generous -timeout buys the whole derivation",
			wait: 5 * time.Minute, remaining: 16 * time.Minute, overhead: waitBudgetReserve, slots: 2,
			want: 5 * time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, trim := fitWaitToBudget(tc.wait, tc.remaining, tc.overhead, tc.slots)
			if got != tc.want {
				t.Errorf("wait = %s, want %s", got, tc.want)
			}
			if (trim != "") != tc.trimmed {
				t.Errorf("trimmed = %t (%q), want %t", trim != "", trim, tc.trimmed)
			}
			if got > tc.wait {
				t.Errorf("the budget fit LENGTHENED the wait, %s > %s: it may only ever trim", got, tc.wait)
			}
			if got < defaultWait {
				t.Errorf("the budget fit produced %s, narrower than the %s this change replaced — it must "+
					"never be able to make a check's window worse than it was", got, defaultWait)
			}
		})
	}
}

// The budget is shared by however many full poll-cycle waits the row performs,
// so the count has to come from the spec and not be assumed to be one. The rows
// whose post-change observation is a second full cycle (CORE-012, CORE-016,
// CORE-022, BASIC-016, AGG-009) are the ones this protects.
func TestWaitSlotsCountsTheSecondFullCycle(t *testing.T) {
	change := func(context.Context, *Driver, map[string]string) error { return nil }

	for _, tc := range []struct {
		name string
		s    spec
		want int
	}{
		{"a plain fetch row", spec{}, 1},
		{"a row with a short post-change settle", spec{Change: change}, 1},
		{"a row with an explicit post-change settle", spec{Change: change, ChangeWait: 20 * time.Second}, 1},
		{"a row asking for a second full cycle", spec{Change: change, ChangeWait: changeWaitFullCycle}, 2},
		{"the sentinel without a Change to trigger it", spec{ChangeWait: changeWaitFullCycle}, 1},
		// IW14-005: an oracled row's PostWait polls the DER for up to a second
		// full poll-cycle window while the southbound write lands, so it is a
		// slot on exactly the same footing as a second fetch cycle.
		{"an oracled row whose PostWait settles", spec{SettlePoll: true}, 2},
		{"a settling row that also re-fetches", spec{Change: change, ChangeWait: changeWaitFullCycle,
			SettlePoll: true}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitSlots(tc.s); got != tc.want {
				t.Errorf("waitSlots = %d, want %d", got, tc.want)
			}
		})
	}
}

// liveOverhead has to include the FIXED post-change settle, or a row that
// sleeps changeSettle after its window budgets as though it did not and the
// trim it computes is too generous by exactly that much.
func TestLiveOverheadIncludesTheFixedSettle(t *testing.T) {
	change := func(context.Context, *Driver, map[string]string) error { return nil }

	if got, want := liveOverhead(spec{}), waitBudgetReserve; got != want {
		t.Errorf("a row with no Change: overhead = %s, want %s", got, want)
	}
	if got, want := liveOverhead(spec{Change: change}), waitBudgetReserve+changeSettle; got != want {
		t.Errorf("a row with a default settle: overhead = %s, want %s", got, want)
	}
	if got, want := liveOverhead(spec{Change: change, ChangeWait: time.Minute}),
		waitBudgetReserve+time.Minute; got != want {
		t.Errorf("a row with an explicit settle: overhead = %s, want %s", got, want)
	}
	// A second FULL cycle is a slot, not overhead: counting it in both places
	// would halve the budget twice.
	if got, want := liveOverhead(spec{Change: change, ChangeWait: changeWaitFullCycle}),
		waitBudgetReserve; got != want {
		t.Errorf("a row asking for a second full cycle: overhead = %s, want %s (the second cycle is a "+
			"slot, not overhead)", got, want)
	}
}

// End to end: a derived window that will not fit the check's own -timeout is
// trimmed rather than allowed to run the check off its deadline, and the
// bundle is told that is what happened.
func TestFetchWaitTrimsADerivedWindowToTheCheckDeadline(t *testing.T) {
	// A 300 s advertisement derives a 630 s window; the check has ~2 minutes.
	rc := waitTestCtx(t, 300, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	got, why := fetchWait(ctx, rc, spec{})

	if got >= 630*time.Second {
		t.Fatalf("wait = %s: a derived window longer than the check's whole -timeout was not trimmed", got)
	}
	if got < defaultWait {
		t.Fatalf("wait = %s, trimmed below the %s constant this replaced", got, defaultWait)
	}
	if !strings.Contains(why, "-timeout") {
		t.Errorf("the explanation must tell the reader the deadline, not the cadence, chose this "+
			"window: %s", why)
	}
}
