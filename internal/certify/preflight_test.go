package certify

// preflight_test.go pins a check whose whole value is that it fires BEFORE the
// evidence exists. Every case here corresponds to a way the bench has actually
// been wrong, or to a way an over-eager check would make a correct bench
// unusable — and the second list matters as much as the first, because a
// preflight operators disable by habit protects nothing.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"csip-tls-test/internal/evidence/bundle"
)

// gridsimAdmin stands up an admin API answering /admin/status the way a gridsim
// does. An empty dataPlane is what a simulator built before it published one
// answers.
func gridsimAdmin(t *testing.T, pid int, dataPlane string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/status" {
			http.NotFound(w, r)
			return
		}
		body := map[string]any{"programs": []any{}, "server_time": 1, "pid": pid, "poll_rate_s": 60}
		if dataPlane != "" {
			body["data_plane"] = dataPlane
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// preflightRunner builds the smallest Runner that can be preflighted.
func preflightRunner(t *testing.T, mutate func(*Options)) (*Runner, *Reporter, *bytes.Buffer) {
	t.Helper()
	opts, _ := baseOptions(t, nil)
	opts.Iface = "enp1s0"
	if mutate != nil {
		mutate(&opts)
	}
	r, err := New(NewRegistry(), catalogFile(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	return r, NewReporter(&console), &console
}

// The headline case: two ports, two processes. An orphan holding the admin API
// answers every question about DUT traffic with "none", and the run publishes
// that as a device that never dialled.
func TestPreflightRefusesAnAdminAPIServingAnotherDataPlane(t *testing.T) {
	admin := gridsimAdmin(t, 4242, "0.0.0.0:11111")
	r, rep, _ := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = admin.URL
	})
	err := r.preflight(context.Background(), rep)
	if err == nil {
		t.Fatal("a gridsim serving :11111 was accepted as the server behind -gridsim :11113")
	}
	for _, want := range []string{"11111", "11113", "4242", "wrong server", "-skip-preflight"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

func TestPreflightAcceptsOneProcessServingBothPorts(t *testing.T) {
	admin := gridsimAdmin(t, 7, "127.0.0.1:11113")
	r, rep, console := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = admin.URL
	})
	if err := r.preflight(context.Background(), rep); err != nil {
		t.Fatalf("a correctly paired gridsim was refused: %v", err)
	}
	if !strings.Contains(console.String(), "one process, both ports") {
		t.Errorf("the passing case says nothing about what it established:\n%s", console)
	}
	if !strings.Contains(console.String(), "pid 7") {
		t.Errorf("the pid that was checked is not reported:\n%s", console)
	}
}

// A wildcard bind serves every local address, so only the port can be compared.
// Refusing 0.0.0.0 would fail preflight on the bench's own configuration.
func TestPreflightAcceptsAWildcardBind(t *testing.T) {
	for _, reported := range []string{"0.0.0.0:11113", "[::]:11113", ":11113"} {
		t.Run(reported, func(t *testing.T) {
			admin := gridsimAdmin(t, 1, reported)
			r, rep, _ := preflightRunner(t, func(o *Options) {
				o.Targets.GridSim = "127.0.0.1:11113"
				o.Targets.GridSimAdmin = admin.URL
			})
			if err := r.preflight(context.Background(), rep); err != nil {
				t.Errorf("a wildcard bind on %s was refused: %v", reported, err)
			}
		})
	}
}

// The -gridsim 127.0.0.1 mistake. It is not merely inconsistent: loopback never
// reaches the capture interface, so the refusal has to say that, or the operator
// fixes the wrong end.
func TestPreflightRefusesALoopbackSplitAndSaysWhyItMatters(t *testing.T) {
	r, rep, _ := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = "http://69.0.0.20:11114"
	})
	err := r.preflight(context.Background(), rep)
	if err == nil {
		t.Fatal("a loopback data plane against a bench-address admin API was accepted")
	}
	for _, want := range []string{"127.0.0.1", "69.0.0.20", "capture interface", "enp1s0", "never crosses"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not explain the capture consequence (%q): %v", want, err)
		}
	}
}

// Different hosts, neither loopback: still two servers, still a misattribution,
// but the capture-interface paragraph would be a lie so it must not appear.
func TestPreflightRefusesAHostMismatchWithoutInventingACaptureProblem(t *testing.T) {
	r, rep, _ := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "69.0.0.20:11113"
		o.Targets.GridSimAdmin = "http://69.0.0.21:11114"
	})
	err := r.preflight(context.Background(), rep)
	if err == nil {
		t.Fatal("two different bench hosts were accepted as one server")
	}
	if strings.Contains(err.Error(), "capture interface") {
		t.Errorf("a non-loopback mismatch was reported as a capture problem: %v", err)
	}
}

// localhost, 127.0.0.1 and ::1 are the same host however they are spelled, and
// a preflight that said otherwise would block every loopback development run.
func TestPreflightTreatsLoopbackSpellingsAsOneHost(t *testing.T) {
	admin := gridsimAdmin(t, 9, "127.0.0.1:11113")
	r, rep, _ := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = strings.Replace(admin.URL, "127.0.0.1", "localhost", 1)
	})
	if err := r.preflight(context.Background(), rep); err != nil {
		t.Errorf("localhost and 127.0.0.1 were treated as different hosts: %v", err)
	}
}

// An admin API that does not answer is fatal, not a warning: every check that
// reads gridsim's observations would return an empty answer indistinguishable
// from a silent DUT, which is the exact confusion this file exists to end.
func TestPreflightRefusesAnUnreachableAdminAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r, rep, _ := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = srv.URL
	})
	err := r.preflight(context.Background(), rep)
	if err == nil {
		t.Fatal("an admin API answering 500 was accepted")
	}
	if !strings.Contains(err.Error(), "indistinguishable from a silent DUT") {
		t.Errorf("the refusal does not say what the failure would have cost: %v", err)
	}
}

// A simulator too old to describe itself is reported, not refused, on an
// EXPLORATORY run: an unproven pairing is weaker than a proven one but it is
// not a proven mismatch, and refusing every previously-built gridsim would
// make -skip-preflight a habit. (A GATING campaign refuses it outright — see
// TestWeakeningSwitchesRefuseGatingRecordExploratory in
// preflight_weakened_test.go.)
func TestPreflightReportsAGridsimThatCannotDescribeItself(t *testing.T) {
	admin := gridsimAdmin(t, 3, "")
	r, rep, console := preflightRunner(t, func(o *Options) {
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = admin.URL
	})
	if err := r.preflight(context.Background(), rep); err != nil {
		t.Fatalf("a gridsim predating the data_plane field was refused: %v", err)
	}
	if !strings.Contains(console.String(), "could not be proven") {
		t.Errorf("the unproven pairing is not reported as unproven:\n%s", console)
	}
	if !reflect.DeepEqual(r.weakened, []string{WeakenedNoDataPlane}) {
		t.Errorf("the unproven pairing was not recorded as weakened: %v", r.weakened)
	}
}

// A run with no bench flags at all — every framework test, and -list — must not
// acquire a network dependency.
func TestPreflightIsSilentWithoutAGridsim(t *testing.T) {
	r, rep, console := preflightRunner(t, nil)
	if err := r.preflight(context.Background(), rep); err != nil {
		t.Fatalf("a run configuring no 2030.5 server was refused: %v", err)
	}
	if console.Len() != 0 {
		t.Errorf("preflight spoke about a bench that was never configured:\n%s", console)
	}
}

// The bypass must work, must be visible on the console, and must reach the
// bundle — an operator asserting a pairing is a different evidentiary position
// from a tool establishing one, and the reader of the findings is entitled to
// know which they are holding.
func TestSkipPreflightIsHonouredAndRecorded(t *testing.T) {
	r, rep, console := preflightRunner(t, func(o *Options) {
		o.SkipPreflight = true
		o.Targets.GridSim = "127.0.0.1:11113"
		o.Targets.GridSimAdmin = "http://69.0.0.20:11114" // would otherwise be refused
	})
	if err := r.preflight(context.Background(), rep); err != nil {
		t.Fatalf("-skip-preflight did not bypass the check: %v", err)
	}
	if !strings.Contains(console.String(), "-skip-preflight") {
		t.Errorf("the bypass is not on the console:\n%s", console)
	}
}

// The check has to fire before the bench is touched, or it is just a slower way
// of finding out. A failing preflight must abandon the run with no capture
// started and no bundle written.
func TestRunStopsAtPreflightBeforeTouchingTheBench(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", func(context.Context, *RunCtx) (Result, error) {
		t.Error("a check ran after preflight had failed")
		return Result{}, nil
	})
	opts, out := baseOptions(t, nil)
	opts.Targets.GridSim = "127.0.0.1:11113"
	opts.Targets.GridSimAdmin = "http://69.0.0.20:11114"
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err == nil {
		t.Fatal("the run proceeded past a failed preflight")
	} else if !strings.Contains(err.Error(), "preflight") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a run that failed preflight wrote a bundle directory")
	}
}

// And the bypass reaches the evidence: a reader of the findings must be able to
// tell an established pairing from an asserted one.
func TestSkipPreflightReachesTheBundle(t *testing.T) {
	cat := catalogFile(t)
	reg := NewRegistry()
	reg.Register("doc-a::A-001", "x", noopCheck)
	opts, out := baseOptions(t, nil)
	opts.SkipPreflight = true
	opts.Targets.GridSim = "127.0.0.1:11113"
	opts.Targets.GridSimAdmin = "http://69.0.0.20:11114"
	opts.Command = []string{"certify", "-skip-preflight"}
	run, err := New(reg, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v\n%s", err, console(opts))
	}
	b, err := bundle.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Run.Note, "preflight SKIPPED") {
		t.Errorf("the bundle does not record the bypass: %q", b.Run.Note)
	}
	if !strings.Contains(b.Run.Note, "assumes a pairing this bundle does not evidence") {
		t.Errorf("the bundle records the bypass without saying what it cost: %q", b.Run.Note)
	}
	if strings.Join(b.Run.Command, " ") != "certify -skip-preflight" {
		t.Errorf("the invocation does not show the flag: %v", b.Run.Command)
	}
}
