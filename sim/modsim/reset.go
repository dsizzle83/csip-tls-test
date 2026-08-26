package main

// reset.go — POST /reset, and the two response envelopes the deterministic
// endpoints answer with.
//
// These live in the sim binary rather than in simapi or sim/southbound on
// purpose. simapi routes requests and stays out of every body's schema (it
// takes raw bytes and hands back whatever the sim returns); sim/southbound
// knows about registers and frames and must not learn about an HTTP API
// version. The binary is the one place that legitimately knows both, so the
// binding between them is here, in about sixty lines, where it can be read.

import (
	"context"
	"fmt"

	"csip-tls-test/sim/simapi"
	sim "csip-tls-test/sim/southbound"
)

// resetSpec is POST /reset's body.
//
// Every field is optional. An empty body means "the as-built baseline, leave
// the poll anchor alone", which is what a row that just wants a known device
// is asking for.
type resetSpec struct {
	// Baseline names the register image to restore. Empty means the as-built
	// image every sim captures at startup.
	Baseline string `json:"baseline,omitempty"`
	// PollAnchor, when given, DECLARES the read request that delimits a poll
	// cycle instead of letting the tap learn it from the traffic (see
	// sim/southbound/poll.go). A bench that knows its client's measurement
	// model can pin it and skip the two-cycle learning phase; one that does
	// not should leave it out and let the tap work it out, then read the
	// answer back from GET /poll.
	//
	// A body that carries the key with an all-zero value CLEARS a previously
	// declared anchor and returns the tap to learning, which is why it is a
	// pointer: absent and "cleared" are different requests.
	PollAnchor *sim.AnchorSpec `json:"poll_anchor,omitempty"`
}

// resetResult is what POST /reset reports back, inside the acknowledgement's
// `result` field. The epoch itself is the acknowledgement's own.
type resetResult struct {
	// Baseline is the image that was restored.
	Baseline string `json:"baseline"`
	// Cleared names, in the order they ran, the fault layers this reset put
	// back. It is reported rather than assumed: "nothing is armed" is a claim
	// a row relies on, and a claim a row relies on should be visible in the
	// bundle rather than trusted.
	Cleared []string `json:"cleared"`
	// Baselines lists every image this sim holds, so a caller that guessed a
	// name wrong sees the alternatives without another round trip.
	Baselines []string `json:"baselines"`
	// PollAnchor reports the anchor in force after the reset.
	PollAnchor sim.AnchorSpec `json:"poll_anchor"`
	// PollAnchorSource is "declared", "learned", or empty while the tap is
	// still learning.
	PollAnchorSource string `json:"poll_anchor_source,omitempty"`
}

// applyReset restores a baseline and reports what it did.
func applyReset(body []byte, baselines *sim.BaselineStore, tap *sim.Tap) (any, error) {
	var spec resetSpec
	if err := simapi.DecodeBody(body, &spec); err != nil {
		return nil, fmt.Errorf("reset: %w", err)
	}
	name := spec.Baseline
	if name == "" {
		name = sim.BaselineName
	}
	cleared, err := baselines.Restore(name)
	if err != nil {
		return nil, err
	}
	out := resetResult{Baseline: name, Cleared: cleared, Baselines: baselines.Names()}
	if tap != nil {
		// The anchor declaration comes AFTER the restore, because a restore
		// resets poll accounting and would otherwise discard the declaration
		// the caller just made in the same request.
		if spec.PollAnchor != nil {
			tap.Polls().Declare(*spec.PollAnchor)
		}
		st := tap.Polls().Snapshot()
		out.PollAnchor, out.PollAnchorSource = st.Anchor, st.AnchorSource
	}
	return out, nil
}

// pollEnvelope and ledgerEnvelope stamp the API version onto the tap's own
// report shapes. The embedded struct's fields are inlined by encoding/json, so
// the body a caller sees is the report plus one field — not the report nested
// inside a wrapper, which would make every field one level deeper for no gain.
type pollEnvelope struct {
	APIVersion string `json:"api_version"`
	sim.PollReport
}

type ledgerEnvelope struct {
	APIVersion string `json:"api_version"`
	sim.LedgerReport
}

func pollBody(r sim.PollReport) pollEnvelope {
	return pollEnvelope{APIVersion: simapi.APIVersion, PollReport: r}
}

func ledgerBody(r sim.LedgerReport) ledgerEnvelope {
	return ledgerEnvelope{APIVersion: simapi.APIVersion, LedgerReport: r}
}

// wireDeterministic registers the four endpoints that turn this simulator into
// a fixture: the epoch counter every mutation acknowledges with, the baseline
// reset, the transaction ledger and the poll barrier.
//
// It is one function, called by main and by the integration test, because the
// value of the test is that it drives WHAT THE BENCH RUNS. A test that
// re-created this wiring would prove that a copy of the binary works.
//
// A nil tap is a supported configuration (-tap=false): /reset still works —
// restoring a baseline needs no wire tap — while /ledger and /poll[/wait] stay
// unregistered, so they answer 501 with a reason a row can quote instead of
// reporting an empty ledger as "the client did nothing".
func wireDeterministic(api *simapi.Server, epoch *sim.Epoch, baselines *sim.BaselineStore, tap *sim.Tap) {
	api.SetEpochFn(epoch.Next)
	api.SetResetFn(func(body []byte) (any, error) {
		return applyReset(body, baselines, tap)
	})
	if tap == nil {
		return
	}
	api.SetLedgerFn(func(q simapi.LedgerQuery) (any, error) {
		return ledgerBody(tap.LedgerReportFor(sim.LedgerQuery{
			SinceEpoch: q.SinceEpoch,
			SinceSeq:   q.SinceSeq,
			Limit:      q.Limit,
		})), nil
	})
	api.SetPollFn(func(ctx context.Context, want uint64) (any, error) {
		// want == 0 is GET /poll: report now, block on nothing.
		if want == 0 {
			return pollBody(tap.Report(true, 0, tap.Polls().Snapshot())), nil
		}
		reached, st := tap.Polls().Wait(ctx, want)
		return pollBody(tap.Report(reached, want, st)), nil
	})
}
