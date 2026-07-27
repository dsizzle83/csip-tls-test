package certify

// observe.go computes how long a passive observation should wait.
//
// Several procedures have a [C] half: a criterion about a connection the DUT
// opens ON ITS OWN SCHEDULE — its southbound Modbus client dialling a device
// sim, its IEEE 2030.5 client dialling the utility server. This bench cannot
// make those happen. Reconfiguring or restarting the DUT to trigger one is a
// configuration change, and on a shared bench that is not available.
//
// So the check waits. How long it waits used to be a constant, and a constant
// is wrong in both directions: too short and a conformant DUT is reported as
// having opened no connection (run 20260726T225512 waited 25 s against a 60 s
// northbound discovery cadence and recorded "no ClientHello from the gateway"
// four times over, none of which was a fact about the gateway); too long and
// every [C]-half case costs minutes it did not need.
//
// The cadence is not a secret. It is in the DUT's own configuration, readable
// over the same read-only introspection channel the RBAC rules database is read
// through. ObservationWait reads it and derives the wait from it, and when it
// cannot, it falls back to a constant and SAYS SO — the explanation travels back
// to the caller so the assertion can carry it.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ObservationSpec describes where a DUT's cadence for one kind of connection is
// configured, and what to do when it cannot be read.
type ObservationSpec struct {
	// What names the connection in the explanation, e.g. "southbound Modbus
	// poll".
	What string
	// ConfigPath is the DUT configuration file holding the cadence.
	ConfigPath string
	// Field is the top-level JSON key, in seconds.
	Field string
	// Fallback is the wait to use when the DUT's configuration cannot be read.
	Fallback time.Duration
	// Param is an operator override key. When the run supplies it, it wins over
	// everything — including the DUT's own configuration, because an operator
	// who knows their bench outranks a heuristic.
	Param string
	// Periods is how many configured periods to wait. Zero means 2, which is
	// the right default for "catch at least one": a period that has just
	// elapsed leaves a whole one inside the window.
	Periods int
	// Slack is added on top. Zero means 5 seconds.
	Slack time.Duration
	// Min and Max bound the result. Zero means 5 s and 3 minutes.
	Min, Max time.Duration
}

// ObservationWait returns how long to wait for the DUT to dial, and a sentence
// explaining where the number came from.
//
// The explanation is not decoration. An assertion that says "no connection
// arrived in 25 s" is only interpretable if the reader knows whether 25 s was
// derived from the device's own cadence or picked out of the air.
func (rc *RunCtx) ObservationWait(ctx context.Context, spec ObservationSpec) (time.Duration, string) {
	periods := spec.Periods
	if periods <= 0 {
		periods = 2
	}
	slack := spec.Slack
	if slack <= 0 {
		slack = 5 * time.Second
	}
	min, max := spec.Min, spec.Max
	if min <= 0 {
		min = 5 * time.Second
	}
	if max <= 0 {
		max = 3 * time.Minute
	}
	clamp := func(d time.Duration) time.Duration {
		switch {
		case d < min:
			return min
		case d > max:
			return max
		default:
			return d
		}
	}

	if spec.Param != "" {
		if v, ok := rc.Param(spec.Param); ok && v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				return d, fmt.Sprintf("%s, set explicitly with -param %s=%s", d, spec.Param, v)
			}
		}
	}

	interval, err := rc.dutSeconds(ctx, spec.ConfigPath, spec.Field)
	if err != nil {
		return clamp(spec.Fallback), fmt.Sprintf(
			"%s (a fallback: the DUT's %s could not be read from %s, so the wait is not derived from the "+
				"device's own cadence — %v)", clamp(spec.Fallback), spec.What, spec.ConfigPath, err)
	}
	wait := clamp(time.Duration(periods)*interval + slack)
	return wait, fmt.Sprintf("%s, derived from the DUT's own %s of %s (%s %s in %s): %d periods plus %s of "+
		"slack, so a period that had just elapsed still leaves a whole one inside the window",
		wait, spec.What, interval, spec.Field, interval, spec.ConfigPath, periods, slack)
}

// dutSeconds reads one top-level integer-seconds field from a DUT config file.
func (rc *RunCtx) dutSeconds(ctx context.Context, path, field string) (time.Duration, error) {
	if rc.Gateway == nil || !rc.Gateway.Available() {
		return 0, fmt.Errorf("gateway introspection is not configured (-gateway-ssh)")
	}
	b, err := rc.Gateway.ReadFile(ctx, path)
	if err != nil {
		return 0, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0, fmt.Errorf("%s does not parse as JSON: %w", path, err)
	}
	raw, ok := doc[field]
	if !ok {
		return 0, fmt.Errorf("%s carries no %q field", path, field)
	}
	var secs float64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return 0, fmt.Errorf("%s: %q is not a number: %w", path, field, err)
	}
	if secs <= 0 {
		return 0, fmt.Errorf("%s: %q is %v, which is not a cadence", path, field, secs)
	}
	return time.Duration(secs * float64(time.Second)), nil
}
