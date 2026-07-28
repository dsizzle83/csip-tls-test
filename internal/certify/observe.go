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
//
// # Whose cadence, though
//
// For the northbound IEEE 2030.5 walk the DUT's configuration is NOT the whole
// answer, and reading it as though it were is a second way to wait the wrong
// amount of time. lexa-gw ships with poll_rate_mode "honor": it paces its walk
// at the pollRate the SERVER advertises, and its own discovery_interval_s is a
// floor beneath that — the rate it will not exceed, not the rate it keeps.
// Against gridsim's stock tree the advertised rate is 900 s while the DUT's
// configured floor is 90, so a window derived from 90 expires twelve minutes
// before the walk it was waiting for, and the "no ClientHello from the gateway"
// that follows is a fact about the harness.
//
// The bench papered over this by launching gridsim with -poll-rate-s 60, which
// made the two numbers close enough to stop mattering. That is a bench
// convention holding up a derivation, and bench conventions drift — silently,
// and into evidence. So when the run has a gridsim admin API, ObservationWait
// ASKS it what pollRate it is advertising and takes max(advertised, configured
// floor): the two rules the DUT applies, applied in the same order. Which
// source won is named in the explanation, because "the wait was 2m5s" and "the
// wait was 2m5s because the server said 60 s" are different claims and only the
// second is one a reader can check.

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
	// ServerPollRate says this connection is the northbound IEEE 2030.5 walk,
	// whose rate the SERVER dictates: the DUT ships in poll_rate_mode "honor"
	// and paces at the advertised pollRate, treating Field as a floor. Set it
	// and the wait is derived from max(the pollRate gridsim reports, Field);
	// leave it false and Field is taken as the cadence itself.
	//
	// It is opt-in per observation rather than global because it is not true of
	// every cadence. The southbound Modbus poll interval is the DUT's own and
	// no 2030.5 pollRate governs it; deriving that window from a 2030.5 server
	// setting would be as wrong as the bug this field fixes, in the other
	// direction.
	ServerPollRate bool
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

	interval, source, err := rc.cadence(ctx, spec)
	if err != nil {
		return clamp(spec.Fallback), fmt.Sprintf(
			"%s (a fallback: %v, so the wait is not derived from the cadence the device actually keeps)",
			clamp(spec.Fallback), err)
	}
	raw := time.Duration(periods)*interval + slack
	wait := clamp(raw)
	why := fmt.Sprintf("%s, derived from %s: %d periods plus %s of slack, so a period that had just elapsed "+
		"still leaves a whole one inside the window", wait, source, periods, slack)
	if wait != raw {
		// A clamped wait presented as "N periods plus slack" is a false
		// sentence: the window is not what the derivation asked for, and a
		// reader deciding whether an empty window means anything needs to know
		// that the ceiling, not the cadence, chose it.
		why += fmt.Sprintf(" — except that came to %s and this observation is bounded to [%s, %s], so the wait "+
			"is the bound and NOT the %d periods the derivation asks for", raw, min, max, periods)
	}
	return wait, why
}

// cadence resolves the period an observation window is built from, and names
// the source in the words the bundle will carry.
//
// The preference chain, and why the order is not arbitrary:
//
//  1. Nothing here outranks the operator; ObservationWait has already returned
//     if -param was given.
//  2. For a ServerPollRate observation, the advertised pollRate and the DUT's
//     configured floor are BOTH consulted and the slower wins, because that is
//     what a poll_rate_mode "honor" client does: it obeys the server's rate but
//     never polls faster than its own floor.
//  3. Otherwise the DUT's configuration is the cadence, as it always was.
//
// A source that cannot be read is not silently dropped from the sentence: when
// the pollRate is unavailable the explanation says the derivation rests on a
// floor, which is the weaker claim, and says why.
func (rc *RunCtx) cadence(ctx context.Context, spec ObservationSpec) (time.Duration, string, error) {
	floor, floorErr := rc.dutSeconds(ctx, spec.ConfigPath, spec.Field)
	floorSource := func() string {
		return fmt.Sprintf("the DUT's own %s of %s (%s %s in %s)",
			spec.What, floor, spec.Field, floor, spec.ConfigPath)
	}
	floorUnreadable := func() error {
		return fmt.Errorf("the DUT's %s could not be read from %s — %v", spec.What, spec.ConfigPath, floorErr)
	}

	if !spec.ServerPollRate {
		if floorErr != nil {
			return 0, "", floorUnreadable()
		}
		return floor, floorSource(), nil
	}

	poll, pollErr := rc.advertisedPollRate(ctx)
	honored := "which is the rate a client in poll_rate_mode \"honor\" — the product default — paces its " +
		"walk at, the configured interval being only a floor beneath it"
	switch {
	case pollErr != nil && floorErr != nil:
		return 0, "", fmt.Errorf("neither cadence could be read: the bench 2030.5 server's advertised "+
			"pollRate — %v — and %v", pollErr, floorUnreadable())
	case pollErr != nil:
		return floor, floorSource() + fmt.Sprintf(", the bench 2030.5 server's advertised pollRate being "+
			"unavailable (%v) — so this rests on a FLOOR and not on the rate the DUT actually keeps, which "+
			"is the server's to choose", pollErr), nil
	case floorErr != nil:
		return poll, fmt.Sprintf("the bench 2030.5 server's advertised pollRate of %s (poll_rate_s from "+
			"%s/admin/status), %s; the DUT's own %s floor was not read into this (%v)",
			poll, rc.GridSim.BaseURL, honored, spec.Field, floorErr), nil
	case poll >= floor:
		return poll, fmt.Sprintf("the bench 2030.5 server's advertised pollRate of %s (poll_rate_s from "+
			"%s/admin/status), %s — it is the slower of that and the DUT's own %s floor of %s (%s in %s), "+
			"and the slower governs", poll, rc.GridSim.BaseURL, honored, spec.What, floor, spec.Field,
			spec.ConfigPath), nil
	default:
		return floor, floorSource() + fmt.Sprintf(", which is slower than the bench 2030.5 server's "+
			"advertised pollRate of %s (poll_rate_s from %s/admin/status) and therefore governs: the DUT "+
			"honours the server's rate but never polls faster than its own floor",
			poll, rc.GridSim.BaseURL), nil
	}
}

// advertisedPollRate asks the bench's 2030.5 server what pollRate it is
// serving. It is a question about the SERVER, so it is asked of the server —
// not inferred from the flag the operator believes it was launched with.
func (rc *RunCtx) advertisedPollRate(ctx context.Context) (time.Duration, error) {
	if rc.GridSim == nil || !rc.GridSim.Available() {
		return 0, fmt.Errorf("no 2030.5 server admin API is configured (-gridsim-admin)")
	}
	var st struct {
		PollRateS uint32 `json:"poll_rate_s"`
	}
	if err := rc.GridSim.Status(ctx, &st); err != nil {
		return 0, err
	}
	if st.PollRateS == 0 {
		return 0, fmt.Errorf("%s/admin/status reports no poll_rate_s (a gridsim predating this field?)",
			rc.GridSim.BaseURL)
	}
	return time.Duration(st.PollRateS) * time.Second, nil
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
