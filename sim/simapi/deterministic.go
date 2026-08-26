package simapi

// deterministic.go — the endpoints that turn a simulator into a FIXTURE.
//
// The four endpoints here exist so a conformance row never has to decide
// anything by elapsed time:
//
//	POST /reset      put the device back to a named baseline, and tell me the
//	                 epoch that is true from
//	POST /fault …    arm something, and tell me the epoch it is armed from
//	GET  /poll/wait  block until the client has finished a poll cycle
//	GET  /ledger     give me the transactions inside that fence
//
// A row that uses them makes exactly one assumption about timing — that the
// client under test eventually polls — and that assumption is bounded by the
// row's own context rather than by a number someone guessed.
//
// # Long-poll and the caller's HTTP timeout
//
// /poll/wait blocks, which means it collides with whatever read timeout the
// caller's HTTP client has (the conformance harness's is 15 s). Rather than
// require every caller to special-case one endpoint, the handler bounds each
// request with the `timeout` query parameter, defaulting to
// defaultPollWaitTimeout and capped at maxPollWaitTimeout, and ALWAYS answers
// 200 — with `reached` saying whether the cycle actually completed. A caller
// that needs to wait longer than one request allows loops on it, which costs
// nothing and keeps the endpoint's contract simple: one request, one bounded
// wait, one honest answer.
//
// A client that disconnects cancels the wait: the handler blocks on
// r.Context(), so an abandoned request frees its goroutine immediately rather
// than holding it for the rest of the timeout.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// APIVersion is this control plane's version, reported by GET /version and
// echoed in every acknowledgement and every deterministic endpoint's response.
//
// It is semantic: the MINOR component goes up when endpoints or fields are
// ADDED (a caller written against an older minor keeps working), the MAJOR
// when an existing endpoint's meaning changes. A row that depends on a
// capability can therefore refuse to run against a sim too old to have it,
// with a message naming the version it needs, instead of misreading a 501 as
// a device finding.
//
//	1.0.0  the original surface: /state /inject /control /fault /registers
//	       /ws /logs, all mutations answering 204 No Content.
//	1.1.0  LAB29-010: /version /reset /ledger (with a bounded min_entries
//	       wait) /poll /poll/wait; mutations
//	       answer {"api_version","epoch"}; POST /fault gains the tap kinds
//	       next_response and unit_id; POST /inject gains registers /
//	       clear_registers, and the unimplemented verb covers every SunSpec
//	       datatype rather than eight of them.
const APIVersion = "1.1.0"

const (
	// defaultPollWaitTimeout is how long one /poll/wait request blocks when
	// the caller names no timeout. It is comfortably under the conformance
	// harness's own 15 s HTTP timeout, so the default never trips it.
	defaultPollWaitTimeout = 10 * time.Second
	// maxPollWaitTimeout bounds one request. A caller that wants longer loops;
	// a caller that asked for an hour by accident does not pin a goroutine for
	// one.
	maxPollWaitTimeout = 5 * time.Minute
)

// Ack is the body every accepted mutation answers with once the sim has
// registered an epoch counter.
type Ack struct {
	APIVersion string `json:"api_version"`
	// Epoch is the control-plane state version AFTER this change: everything
	// stamped with it or later happened under the new state.
	Epoch uint64 `json:"epoch"`
	// Result is whatever the handler wanted to report (POST /reset uses it);
	// omitted when there is nothing to add.
	Result any `json:"result,omitempty"`
}

// Version is GET /version's body.
type Version struct {
	APIVersion string   `json:"api_version"`
	Endpoints  []string `json:"endpoints"`
}

// ackMutation writes the acknowledgement for an accepted mutation: a JSON body
// carrying the new epoch when the sim has an epoch counter, and the historic
// 204 No Content when it has not.
func (s *Server) ackMutation(w http.ResponseWriter, result any) {
	s.mu.Lock()
	fn := s.epochFn
	s.mu.Unlock()
	if fn == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, Ack{APIVersion: APIVersion, Epoch: fn(), Result: result})
}

// handleVersion reports the API version and the endpoints THIS sim actually
// implements — the ones whose handler is registered, not the ones the package
// can offer. A caller can therefore tell "this sim is too old" from "this sim
// does not do that", which are different reasons for the same 501.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	v := Version{APIVersion: APIVersion, Endpoints: []string{"GET /version", "GET /state", "GET /logs", "GET /ws"}}
	s.mu.Lock()
	fault, reset, ledger, poll, epoch := s.faultFn, s.resetFn, s.ledgerFn, s.pollFn, s.epochFn
	s.mu.Unlock()
	if s.injectFn != nil {
		v.Endpoints = append(v.Endpoints, "POST /inject")
	}
	if s.controlFn != nil {
		v.Endpoints = append(v.Endpoints, "POST /control")
	}
	if s.registersFn != nil {
		v.Endpoints = append(v.Endpoints, "GET /registers")
	}
	if fault != nil {
		v.Endpoints = append(v.Endpoints, "POST /fault")
	}
	if reset != nil {
		v.Endpoints = append(v.Endpoints, "POST /reset")
	}
	if ledger != nil {
		v.Endpoints = append(v.Endpoints, "GET /ledger")
	}
	if poll != nil {
		v.Endpoints = append(v.Endpoints, "GET /poll", "GET /poll/wait")
	}
	if epoch != nil {
		v.Endpoints = append(v.Endpoints, "epoch-acknowledged mutations")
	}
	writeJSON(w, v)
}

// handleReset restores a named baseline register image.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	fn := s.resetFn
	s.mu.Unlock()
	if fn == nil {
		http.Error(w, "baseline reset is not supported by this simulator", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := fn(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.ackMutation(w, result)
}

// handleLedger answers the sim's own transaction record.
func (s *Server) handleLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	fn := s.ledgerFn
	s.mu.Unlock()
	if fn == nil {
		http.Error(w, "this simulator keeps no transaction ledger (it serves no Modbus wire tap)",
			http.StatusNotImplemented)
		return
	}
	q := r.URL.Query()
	sinceEpoch, err := uintParam(q.Get("since_epoch"))
	if err != nil {
		http.Error(w, "since_epoch: "+err.Error(), http.StatusBadRequest)
		return
	}
	sinceSeq, err := uintParam(q.Get("since_seq"))
	if err != nil {
		http.Error(w, "since_seq: "+err.Error(), http.StatusBadRequest)
		return
	}
	limit, err := uintParam(q.Get("limit"))
	if err != nil {
		http.Error(w, "limit: "+err.Error(), http.StatusBadRequest)
		return
	}
	minEntries, err := uintParam(q.Get("min_entries"))
	if err != nil {
		http.Error(w, "min_entries: "+err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	// min_entries turns this into a bounded wait, with the same contract
	// /poll/wait has: the request bounds ITSELF, always answers 200, and the
	// body says what it found. A caller that needs longer loops on it.
	if minEntries > 0 {
		d, err := durationParam(q.Get("timeout"))
		if err != nil {
			http.Error(w, "timeout: "+err.Error(), http.StatusBadRequest)
			return
		}
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	page, err := fn(ctx, LedgerQuery{
		SinceEpoch: sinceEpoch,
		SinceSeq:   sinceSeq,
		Limit:      int(limit),
		MinEntries: int(minEntries),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, page)
}

// handlePoll reports poll-cycle accounting without blocking.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	s.servePoll(w, r, false)
}

// handlePollWait blocks until the requested cycle has completed, this
// request's timeout elapses, or the caller goes away.
func (s *Server) handlePollWait(w http.ResponseWriter, r *http.Request) {
	s.servePoll(w, r, true)
}

func (s *Server) servePoll(w http.ResponseWriter, r *http.Request, wait bool) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	fn := s.pollFn
	s.mu.Unlock()
	if fn == nil {
		http.Error(w, "this simulator does not count the client's poll cycles (it serves no Modbus "+
			"wire tap)", http.StatusNotImplemented)
		return
	}
	ctx := r.Context()
	var want uint64
	if wait {
		q := r.URL.Query()
		// `epoch` is the parameter name the LAB29-010 contract fixes; `poll`
		// is accepted as the clearer synonym, because this endpoint's number
		// is a POLL-CYCLE ordinal and NOT the control-plane epoch that
		// /ledger?since_epoch and the mutation acknowledgements speak of.
		// Two different counters, both called "epoch" somewhere, is a trap;
		// naming both spellings and documenting the difference is the fix.
		raw := q.Get("epoch")
		if raw == "" {
			raw = q.Get("poll")
		}
		var err error
		if want, err = uintParam(raw); err != nil {
			http.Error(w, "epoch: "+err.Error(), http.StatusBadRequest)
			return
		}
		if want == 0 {
			http.Error(w, "epoch: a poll-cycle ordinal of 0 has already completed by definition; ask "+
				"for the cycle you want to wait for (GET /poll reports the current count)",
				http.StatusBadRequest)
			return
		}
		d, err := durationParam(q.Get("timeout"))
		if err != nil {
			http.Error(w, "timeout: "+err.Error(), http.StatusBadRequest)
			return
		}
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	out, err := fn(ctx, want)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, out)
}

// uintParam parses an optional unsigned query parameter; empty is 0.
func uintParam(v string) (uint64, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a non-negative integer", v)
	}
	return n, nil
}

// durationParam parses the `timeout` query parameter. Empty gives the default;
// a bare number is read as seconds, so `timeout=30` and `timeout=30s` mean the
// same thing and neither is a silent misreading of the other.
func durationParam(v string) (time.Duration, error) {
	if v == "" {
		return defaultPollWaitTimeout, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		secs, ferr := strconv.ParseFloat(v, 64)
		if ferr != nil {
			return 0, fmt.Errorf("%q is neither a duration (10s, 1m30s) nor a number of seconds", v)
		}
		d = time.Duration(secs * float64(time.Second))
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q is not a positive duration", v)
	}
	if d > maxPollWaitTimeout {
		d = maxPollWaitTimeout
	}
	return d, nil
}

// DecodeBody decodes a request body into v, treating an empty body as "no
// fields set" rather than as an error — every field of a /reset body is
// optional with a documented default, and a caller that posts nothing means
// "the default baseline", not "a malformed request".
//
// Exported because the sim binaries, not this package, own the shape of a
// /reset body: simapi routes it and stays out of its schema.
func DecodeBody(body []byte, v any) error {
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}
