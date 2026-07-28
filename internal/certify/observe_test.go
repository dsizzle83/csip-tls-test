package certify

// observe_test.go pins the fix for a class of finding that was never about the
// DUT: a passive [C]-half observation that waited a CONSTANT.
//
// Run 20260726T225512 waited 25 s for connections the gateway opens on a 60 s
// northbound cadence, and recorded "no ClientHello from the gateway" on four
// assertions. Every one of those was a fact about the constant.
//
// The second half of the file pins the sequel: a wait derived from the DUT's
// configured discovery interval is still wrong for the northbound walk, because
// that interval is a FLOOR and the rate is the server's to advertise. Those
// tests exist to keep the harness reading the same number the device reads.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// gatewayServing returns a Gateway whose ReadFile answers with the given file
// contents, keyed by path, and errors for anything else.
func gatewayServing(files map[string]string) *Gateway {
	return &Gateway{
		SSH: "test",
		Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			path := args[len(args)-1]
			body, ok := files[path]
			if !ok {
				return nil, errNoSuchFileOnDUT
			}
			return []byte(body), nil
		},
	}
}

var errNoSuchFileOnDUT = errString("cat: can't open: No such file or directory")

type errString string

func (e errString) Error() string { return string(e) }

func TestObservationWaitComesFromTheDUTsOwnCadence(t *testing.T) {
	rc := &RunCtx{Gateway: gatewayServing(map[string]string{
		"/etc/lexa/northbound.json": `{"v":1,"discovery_interval_s":60,"other":"x"}`,
	})}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What:       "IEEE 2030.5 discovery interval",
		ConfigPath: "/etc/lexa/northbound.json",
		Field:      "discovery_interval_s",
		Fallback:   25 * time.Second,
	})
	// 2 periods of 60 s plus 5 s of slack.
	if want := 125 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s (2 × the DUT's own 60 s cadence, plus slack)", got, want)
	}
	if got <= 25*time.Second {
		t.Error("the derived wait is no longer than the constant that produced the false negatives")
	}
	for _, want := range []string{"1m0s", "discovery_interval_s", "/etc/lexa/northbound.json"} {
		if !strings.Contains(why, want) {
			t.Errorf("the explanation does not mention %q: %s", want, why)
		}
	}
}

// TestObservationWaitFallsBackAndSaysSo: a wait a reader cannot trace to the
// device is still usable, but it must never be presented as if it had been
// derived. "Nothing arrived in 25 s" only means something if the reader knows
// where 25 s came from.
func TestObservationWaitFallsBackAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name string
		rc   *RunCtx
	}{
		{"no gateway introspection", &RunCtx{Gateway: &Gateway{}}},
		{"file absent", &RunCtx{Gateway: gatewayServing(nil)}},
		{"field absent", &RunCtx{Gateway: gatewayServing(map[string]string{
			"/etc/lexa/modbus.json": `{"v":1}`,
		})}},
		{"field is not a cadence", &RunCtx{Gateway: gatewayServing(map[string]string{
			"/etc/lexa/modbus.json": `{"poll_interval_s":0}`,
		})}},
		{"not JSON at all", &RunCtx{Gateway: gatewayServing(map[string]string{
			"/etc/lexa/modbus.json": `not json`,
		})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := tc.rc.ObservationWait(context.Background(), ObservationSpec{
				What:       "southbound Modbus poll interval",
				ConfigPath: "/etc/lexa/modbus.json",
				Field:      "poll_interval_s",
				Fallback:   45 * time.Second,
			})
			if got != 45*time.Second {
				t.Fatalf("wait = %s, want the 45s fallback", got)
			}
			if !strings.Contains(why, "fallback") {
				t.Errorf("the explanation must say the number is a fallback: %s", why)
			}
			if !strings.Contains(why, "could not be read") {
				t.Errorf("the explanation must say why it fell back: %s", why)
			}
		})
	}
}

func TestObservationWaitHonoursTheOperatorOverride(t *testing.T) {
	rc := &RunCtx{
		Gateway: gatewayServing(map[string]string{
			"/etc/lexa/modbus.json": `{"poll_interval_s":10}`,
		}),
		Params: map[string]string{"ssm.client_wait": "3s"},
	}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What:       "southbound Modbus poll interval",
		ConfigPath: "/etc/lexa/modbus.json",
		Field:      "poll_interval_s",
		Fallback:   45 * time.Second,
		Param:      "ssm.client_wait",
	})
	if got != 3*time.Second {
		t.Fatalf("wait = %s, want the operator's 3s: an operator who knows their bench outranks a heuristic", got)
	}
	if !strings.Contains(why, "-param ssm.client_wait") {
		t.Errorf("the explanation must name the override: %s", why)
	}
}

// gridsimServing stands up an admin API answering GET /admin/status with the
// given advertised pollRate. A rate of 0 answers a status without the field,
// which is what a gridsim built before the field existed serves.
func gridsimServing(t *testing.T, pollRateS uint32) *AdminClient {
	t.Helper()
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
	return NewAdminClient(srv.URL, srv.Client())
}

// TestObservationWaitPrefersTheHonouredPollRate is the fix: the DUT paces its
// 2030.5 walk at the rate the SERVER advertises, so a window derived from the
// device's configured floor is a window derived from the wrong number. Here the
// server says 300 s against a 90 s floor, and a floor-derived wait would have
// expired seven minutes before the walk it was waiting for.
func TestObservationWaitPrefersTheHonouredPollRate(t *testing.T) {
	rc := &RunCtx{
		Gateway: gatewayServing(map[string]string{
			"/etc/lexa/northbound.json": `{"discovery_interval_s":90}`,
		}),
		GridSim: gridsimServing(t, 300),
	}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What:           "IEEE 2030.5 discovery interval",
		ConfigPath:     "/etc/lexa/northbound.json",
		Field:          "discovery_interval_s",
		Fallback:       90 * time.Second,
		ServerPollRate: true,
		Max:            30 * time.Minute,
	})
	if want := 605 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s (2 × the advertised 300 s pollRate plus slack, not the 90 s floor)", got, want)
	}
	for _, want := range []string{"pollRate", "5m0s", "poll_rate_s", "/admin/status", "honor", "floor"} {
		if !strings.Contains(why, want) {
			t.Errorf("the explanation does not mention %q, so a reader cannot tell which source chose the "+
				"wait: %s", want, why)
		}
	}
}

// A floor slower than the advertised rate governs, because a client honouring
// pollRate still never polls faster than its own configured minimum.
func TestObservationWaitTakesTheSlowerOfPollRateAndFloor(t *testing.T) {
	rc := &RunCtx{
		Gateway: gatewayServing(map[string]string{
			"/etc/lexa/northbound.json": `{"discovery_interval_s":120}`,
		}),
		GridSim: gridsimServing(t, 60),
	}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What:           "IEEE 2030.5 discovery interval",
		ConfigPath:     "/etc/lexa/northbound.json",
		Field:          "discovery_interval_s",
		Fallback:       90 * time.Second,
		ServerPollRate: true,
		Max:            30 * time.Minute,
	})
	if want := 245 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s (2 × the 120 s floor plus slack: the floor is the slower of the two)", got, want)
	}
	if !strings.Contains(why, "1m0s") || !strings.Contains(why, "discovery_interval_s") {
		t.Errorf("the explanation must name BOTH candidates and say which governed: %s", why)
	}
}

// A gridsim that cannot be asked must not silently become a gridsim that agrees
// with the floor: the wait still happens, but the explanation has to say the
// derivation rests on a floor rather than on the honoured rate.
func TestObservationWaitSaysWhenThePollRateWasUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gridsim *AdminClient
	}{
		{"no admin API configured", nil},
		{"a gridsim predating poll_rate_s", gridsimServing(t, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := &RunCtx{
				Gateway: gatewayServing(map[string]string{
					"/etc/lexa/northbound.json": `{"discovery_interval_s":60}`,
				}),
				GridSim: tc.gridsim,
			}
			got, why := rc.ObservationWait(context.Background(), ObservationSpec{
				What:           "IEEE 2030.5 discovery interval",
				ConfigPath:     "/etc/lexa/northbound.json",
				Field:          "discovery_interval_s",
				Fallback:       90 * time.Second,
				ServerPollRate: true,
			})
			if want := 125 * time.Second; got != want {
				t.Fatalf("wait = %s, want the floor-derived %s", got, want)
			}
			if !strings.Contains(why, "FLOOR") {
				t.Errorf("the explanation must say the derivation rests on a floor: %s", why)
			}
			if !strings.Contains(why, "unavailable") {
				t.Errorf("the explanation must say the pollRate could not be had: %s", why)
			}
		})
	}
}

// An observation that is not the northbound walk must not consult a 2030.5
// server at all. The southbound Modbus poll is the gateway's own cadence, and
// borrowing a northbound rate for it would be the same bug facing the other way.
func TestObservationWaitLeavesNonPollRateCadencesAlone(t *testing.T) {
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rc := &RunCtx{
		Gateway: gatewayServing(map[string]string{
			"/etc/lexa/modbus.json": `{"poll_interval_s":30}`,
		}),
		GridSim: NewAdminClient(srv.URL, srv.Client()),
	}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What:       "southbound Modbus poll interval",
		ConfigPath: "/etc/lexa/modbus.json",
		Field:      "poll_interval_s",
		Fallback:   45 * time.Second,
	})
	if want := 65 * time.Second; got != want {
		t.Fatalf("wait = %s, want %s", got, want)
	}
	if asked {
		t.Error("the 2030.5 server was consulted about the gateway's southbound Modbus cadence")
	}
	if strings.Contains(why, "pollRate") {
		t.Errorf("the explanation drags a 2030.5 pollRate into a Modbus observation: %s", why)
	}
}

// The operator's -param still outranks everything, including a live server.
func TestObservationWaitOverrideBeatsThePollRate(t *testing.T) {
	rc := &RunCtx{
		Gateway: gatewayServing(map[string]string{"/etc/lexa/northbound.json": `{"discovery_interval_s":90}`}),
		GridSim: gridsimServing(t, 600),
		Params:  map[string]string{"pki.identity_wait": "4s"},
	}
	got, _ := rc.ObservationWait(context.Background(), ObservationSpec{
		What:           "IEEE 2030.5 discovery interval",
		ConfigPath:     "/etc/lexa/northbound.json",
		Field:          "discovery_interval_s",
		Fallback:       90 * time.Second,
		Param:          "pki.identity_wait",
		ServerPollRate: true,
	})
	if got != 4*time.Second {
		t.Fatalf("wait = %s, want the operator's 4s", got)
	}
}

// A wait the ceiling chose is not a wait the cadence chose, and an empty window
// means something different in each case. Say which.
func TestObservationWaitSaysWhenItWasClamped(t *testing.T) {
	rc := &RunCtx{Gateway: gatewayServing(map[string]string{
		"/etc/lexa/slow.json": `{"interval_s":600}`,
	})}
	got, why := rc.ObservationWait(context.Background(), ObservationSpec{
		What: "a cadence longer than the ceiling", ConfigPath: "/etc/lexa/slow.json",
		Field: "interval_s", Fallback: time.Minute,
	})
	if got != 3*time.Minute {
		t.Fatalf("wait = %s, want the 3m ceiling", got)
	}
	if !strings.Contains(why, "NOT the 2 periods") {
		t.Errorf("a clamped wait is presented as though the derivation chose it: %s", why)
	}
}

func TestObservationWaitIsClamped(t *testing.T) {
	rc := &RunCtx{Gateway: gatewayServing(map[string]string{
		"/etc/lexa/slow.json": `{"interval_s":86400}`,
	})}
	got, _ := rc.ObservationWait(context.Background(), ObservationSpec{
		What: "a cadence nobody should wait out", ConfigPath: "/etc/lexa/slow.json",
		Field: "interval_s", Fallback: time.Minute,
	})
	if got > 3*time.Minute {
		t.Fatalf("wait = %s, want it clamped: a run must not block for a day because a config says so", got)
	}
}
