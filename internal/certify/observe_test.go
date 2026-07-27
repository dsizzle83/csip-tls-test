package certify

// observe_test.go pins the fix for a class of finding that was never about the
// DUT: a passive [C]-half observation that waited a CONSTANT.
//
// Run 20260726T225512 waited 25 s for connections the gateway opens on a 60 s
// northbound cadence, and recorded "no ClientHello from the gateway" on four
// assertions. Every one of those was a fact about the constant.

import (
	"context"
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
