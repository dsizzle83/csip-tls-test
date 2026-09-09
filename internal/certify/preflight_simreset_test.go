package certify

// preflight_simreset_test.go pins WP7-T6's gating sim reset
// (preflightSimReset, preflight.go): a GATING campaign that cannot PROVE its
// southbound sims and gridsim were reset to a known state before case 1 must
// refuse, exactly like every other unprovable() precondition; an exploratory
// run gets the same gap as a WARN and keeps going.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// simResetServer answers POST /reset. status/body let a test drive both the
// success shape (200 + {"api_version":..,"epoch":N}) and the failure shape a
// sim built before it supported reset answers (501).
func simResetServer(t *testing.T, status int, epoch uint64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/reset" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "not implemented", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"api_version": "1.1.0", "epoch": epoch})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPreflightSimReset_RefusesA501OnGatingCampaign(t *testing.T) {
	srv := simResetServer(t, http.StatusNotImplemented, 0)
	r := &Runner{campaign: CampaignSpec{Name: "csip"},
		opts: Options{Targets: Targets{ModSimAPI: srv.URL}, HTTP: http.DefaultClient}}
	err := r.preflightSimReset(context.Background(), NewReporter(&discardWriter{}))
	if err == nil {
		t.Fatal("a GATING campaign accepted a sim that answered 501 to POST /reset")
	}
	for _, want := range []string{"modsim", "GATING", "QAGAMUT2-001", "POST /reset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestPreflightSimReset_NeverResetsOnAnExploratoryRun proves the mutating
// side effect (POST /reset actually wipes the sim's state) is gated on
// GATING alone, unlike every non-mutating unprovable() precondition in this
// file (preflightCitation, preflightSigning, preflight's own pairing check),
// which always run and let unprovable() itself decide fatal-vs-warn. A quick
// single-uid poke against a live-shared bench must not silently wipe a
// sim's injected/faulted state out from under whatever else was using it —
// see preflightSimReset's own doc for why the task's own wording ("on
// GATING campaigns, resets...") is exactly this posture, not
// unprovable()'s.
func TestPreflightSimReset_NeverResetsOnAnExploratoryRun(t *testing.T) {
	resetHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reset" {
			resetHit = true
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	r := &Runner{ // no campaign declared -> exploratory
		opts: Options{Targets: Targets{ModSimAPI: srv.URL}, HTTP: http.DefaultClient}}
	var console strings.Builder
	if err := r.preflightSimReset(context.Background(), NewReporter(&console)); err != nil {
		t.Fatalf("an EXPLORATORY run was refused: %v", err)
	}
	if resetHit {
		t.Fatal("preflightSimReset issued POST /reset on an EXPLORATORY run — a quick poke must not " +
			"mutate a live-shared sim's state")
	}
	if console.String() != "" {
		t.Errorf("an exploratory run printed something about sim reset, want silence (it never runs "+
			"outside a gating campaign):\n%s", console.String())
	}
}

func TestPreflightSimReset_SucceedsAndRecordsTheEpoch(t *testing.T) {
	srv := simResetServer(t, http.StatusOK, 7)
	r := &Runner{campaign: CampaignSpec{Name: "csip"},
		opts: Options{Targets: Targets{ModSimAPI: srv.URL}, HTTP: http.DefaultClient}}
	var console strings.Builder
	if err := r.preflightSimReset(context.Background(), NewReporter(&console)); err != nil {
		t.Fatalf("a successful POST /reset was refused: %v", err)
	}
	if !strings.Contains(console.String(), "modsim@epoch=7") {
		t.Errorf("the run's transcript does not record the reset epoch:\n%s", console.String())
	}
}

func TestPreflightSimReset_NoopWhenNothingIsConfigured(t *testing.T) {
	r := &Runner{campaign: CampaignSpec{Name: "csip"}, opts: Options{HTTP: http.DefaultClient}}
	var console strings.Builder
	if err := r.preflightSimReset(context.Background(), NewReporter(&console)); err != nil {
		t.Fatalf("a GATING campaign with no sim or gridsim admin API configured was refused: %v", err)
	}
	if !strings.Contains(console.String(), "nothing to reset") {
		t.Errorf("the run's transcript does not explain why nothing was reset:\n%s", console.String())
	}
}

func TestPreflightSimReset_NoopOnExploratoryRunWithNothingConfigured(t *testing.T) {
	r := &Runner{opts: Options{HTTP: http.DefaultClient}} // no campaign, no targets
	if err := r.preflightSimReset(context.Background(), NewReporter(&discardWriter{})); err != nil {
		t.Fatalf("an exploratory run with nothing configured was refused: %v", err)
	}
}

// gridsimAdminWithPrograms answers GET /admin/status with the given program
// ids and records every DELETE it receives, so a test can prove
// clearGridSimPrograms actually reached every one of them.
type gridsimAdminWithPrograms struct {
	srv     *httptest.Server
	deletes []string // "<path> program=<id>"
}

func newGridsimAdminWithPrograms(t *testing.T, ids []int) *gridsimAdminWithPrograms {
	t.Helper()
	g := &gridsimAdminWithPrograms{}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin/status" && r.Method == http.MethodGet:
			type prog struct {
				ID int `json:"id"`
			}
			progs := make([]prog, 0, len(ids))
			for _, id := range ids {
				progs = append(progs, prog{ID: id})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"programs": progs, "server_time": 1})
		case r.Method == http.MethodDelete:
			var body struct {
				Program int `json:"program"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			g.deletes = append(g.deletes, r.URL.Path+" program="+strconv.Itoa(body.Program))
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func TestPreflightSimReset_ClearsEveryGridSimProgram(t *testing.T) {
	g := newGridsimAdminWithPrograms(t, []int{0, 3})
	r := &Runner{campaign: CampaignSpec{Name: "csip"},
		opts: Options{Targets: Targets{GridSimAdmin: g.srv.URL}, HTTP: http.DefaultClient}}
	var console strings.Builder
	if err := r.preflightSimReset(context.Background(), NewReporter(&console)); err != nil {
		t.Fatalf("clearing gridsim's programs was refused: %v", err)
	}
	want := map[string]bool{
		"/admin/control program=0": false, "/admin/curve program=0": false,
		"/admin/control program=3": false, "/admin/curve program=3": false,
	}
	for _, d := range g.deletes {
		want[d] = true
	}
	for k, hit := range want {
		if !hit {
			t.Errorf("clearGridSimPrograms never issued DELETE %s", k)
		}
	}
	if !strings.Contains(console.String(), "2 program(s) cleared") {
		t.Errorf("the run's transcript does not record how many programs were cleared:\n%s", console.String())
	}
}

func TestPreflightSimReset_RefusesWhenGridSimStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	r := &Runner{campaign: CampaignSpec{Name: "csip"},
		opts: Options{Targets: Targets{GridSimAdmin: srv.URL}, HTTP: http.DefaultClient}}
	err := r.preflightSimReset(context.Background(), NewReporter(&discardWriter{}))
	if err == nil {
		t.Fatal("a GATING campaign accepted a gridsim whose /admin/status could not be read")
	}
	for _, want := range []string{"GATING", "gridsim", "program"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// discardWriter is an io.Writer that drops everything, for tests that assert
// nothing about the console transcript.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestSimResetTargets_ExcludesTheMetricsEndpoint pins the 2026-09-09 bench
// finding: -metrics-endpoint lands in Targets.Extra[TargetMetrics] and must
// never be treated as a simulator to reset.
func TestSimResetTargets_ExcludesTheMetricsEndpoint(t *testing.T) {
	var tg Targets
	tg.WithEndpoint(TargetMetrics, "http://127.0.0.1:9102/metrics")
	tg.WithEndpoint("batsim", "http://69.0.0.11:6050")
	var names []string
	for _, s := range simResetTargets(tg) {
		if s.url != "" {
			names = append(names, s.name)
		}
	}
	if len(names) != 1 || names[0] != "batsim" {
		t.Fatalf("simResetTargets = %v, want only the sim sidecar (batsim), never %q", names, TargetMetrics)
	}
}
