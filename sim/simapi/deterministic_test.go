package simapi

// deterministic_test.go drives the four endpoints that turn a simulator into a
// fixture, through a real HTTP server on a real port — the same path the
// conformance harness's SimClient takes.
//
// The properties under test are contractual rather than incidental:
//
//   - a mutation acknowledges with the epoch it is in force FROM, and with the
//     historic 204 when the sim registered no epoch counter;
//   - /poll/wait bounds ITSELF and answers 200 with reached=false rather than
//     erroring, so a caller's HTTP timeout is never the thing that decides a
//     conformance verdict;
//   - a caller that goes away cancels the wait;
//   - /ledger's query parameters are parsed strictly, because a mistyped fence
//     that silently became "everything" would hand a row the previous test
//     case's transactions.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rig starts a Server on a free port and returns its base URL.
type rig struct {
	base  string
	srv   *Server
	epoch atomic.Uint64
}

func newRig(t *testing.T) *rig {
	t.Helper()
	// Ask the OS for a free port, then hand that port to New (which binds it
	// itself). The listener is closed first so the bind can succeed; a race
	// with another process is possible in principle and has never been the
	// flake in practice, and it is the only way to use New's own signature.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	r := &rig{base: "http://" + addr}
	r.srv = New(addr, func() any { return map[string]any{"ok": true} }, nil, nil, nil)
	waitServing(t, r.base)
	return r
}

func waitServing(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/version")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
	}
	t.Fatalf("the simapi server at %s never came up", base)
}

func (r *rig) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(r.base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, buf[:n]
}

func (r *rig) post(t *testing.T, path, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(r.base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, buf[:n]
}

// TestUnregisteredEndpointsAnswer501WithAReason: a sim that cannot do
// something must say so in a way a row can quote, not fail obscurely.
func TestUnregisteredEndpointsAnswer501WithAReason(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct{ method, path, want string }{
		{"POST", "/reset", "baseline reset"},
		{"GET", "/ledger", "transaction ledger"},
		{"GET", "/poll", "poll cycles"},
		{"GET", "/poll/wait", "poll cycles"},
	} {
		var code int
		var body []byte
		if tc.method == "GET" {
			code, body = r.get(t, tc.path)
		} else {
			code, body = r.post(t, tc.path, "{}")
		}
		if code != http.StatusNotImplemented {
			t.Errorf("%s %s = %d, want 501", tc.method, tc.path, code)
		}
		if !strings.Contains(string(body), tc.want) {
			t.Errorf("%s %s said %q, want a reason mentioning %q", tc.method, tc.path, body, tc.want)
		}
	}
}

// TestVersionListsWhatThisSimImplements — a caller can tell "too old" from
// "does not do that", which are different reasons for the same 501.
func TestVersionListsWhatThisSimImplements(t *testing.T) {
	r := newRig(t)
	code, body := r.get(t, "/version")
	if code != http.StatusOK {
		t.Fatalf("GET /version = %d", code)
	}
	var v Version
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if v.APIVersion != APIVersion {
		t.Errorf("api_version = %q, want %q", v.APIVersion, APIVersion)
	}
	if joined := strings.Join(v.Endpoints, " "); strings.Contains(joined, "/ledger") {
		t.Errorf("/version advertises /ledger on a sim with no ledger handler: %v", v.Endpoints)
	}

	r.srv.SetLedgerFn(func(context.Context, LedgerQuery) (any, error) { return nil, nil })
	r.srv.SetEpochFn(func() uint64 { return 1 })
	_, body = r.get(t, "/version")
	_ = json.Unmarshal(body, &v)
	joined := strings.Join(v.Endpoints, " ")
	if !strings.Contains(joined, "GET /ledger") {
		t.Errorf("/version does not advertise /ledger after it was registered: %v", v.Endpoints)
	}
	if !strings.Contains(joined, "epoch") {
		t.Errorf("/version does not advertise epoch-acknowledged mutations: %v", v.Endpoints)
	}
}

// TestMutationsAcknowledgeWithTheEpoch is the contract every fence rests on.
func TestMutationsAcknowledgeWithTheEpoch(t *testing.T) {
	r := newRig(t)
	r.srv.SetFaultFn(func([]byte) error { return nil })

	// With no epoch counter, the historic 204 — byte-identical to the surface
	// every existing caller was written against.
	if code, _ := r.post(t, "/fault", `{"kind":"tcp_drop"}`); code != http.StatusNoContent {
		t.Fatalf("POST /fault with no epoch counter = %d, want 204", code)
	}

	r.srv.SetEpochFn(func() uint64 { return r.epoch.Add(1) })
	code, body := r.post(t, "/fault", `{"kind":"tcp_drop"}`)
	if code != http.StatusOK {
		t.Fatalf("POST /fault = %d, want 200 (%s)", code, body)
	}
	var ack Ack
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("decode ack: %v (%s)", err, body)
	}
	if ack.Epoch != 1 {
		t.Errorf("epoch = %d, want 1", ack.Epoch)
	}
	if ack.APIVersion != APIVersion {
		t.Errorf("api_version = %q, want %q", ack.APIVersion, APIVersion)
	}

	// Every accepted mutation bumps exactly once, whichever endpoint it was.
	_, body = r.post(t, "/fault", `{"kind":"tcp_drop"}`)
	_ = json.Unmarshal(body, &ack)
	if ack.Epoch != 2 {
		t.Errorf("a second mutation reported epoch %d, want 2 — one bump per accepted request", ack.Epoch)
	}

	// A REFUSED mutation must not move the fence, or a row would fence on an
	// epoch nothing happened at.
	r.srv.SetFaultFn(func([]byte) error { return fmt.Errorf("no such kind") })
	if code, _ := r.post(t, "/fault", `{"kind":"nope"}`); code != http.StatusBadRequest {
		t.Fatalf("a refused fault answered %d, want 400", code)
	}
	if got := r.epoch.Load(); got != 2 {
		t.Fatalf("the epoch advanced to %d on a REFUSED mutation; a fence must name a change that "+
			"actually happened", got)
	}
}

// TestResetCarriesItsResult — POST /reset's body is reported inside the
// acknowledgement, so "nothing is armed" is visible rather than trusted.
func TestResetCarriesItsResult(t *testing.T) {
	r := newRig(t)
	r.srv.SetEpochFn(func() uint64 { return r.epoch.Add(1) })
	r.srv.SetResetFn(func(body []byte) (any, error) {
		var spec struct {
			Baseline string `json:"baseline"`
		}
		if err := DecodeBody(body, &spec); err != nil {
			return nil, err
		}
		if spec.Baseline == "nope" {
			return nil, fmt.Errorf("no baseline named %q", spec.Baseline)
		}
		return map[string]any{"baseline": spec.Baseline, "cleared": []string{"a", "b"}}, nil
	})

	code, body := r.post(t, "/reset", `{"baseline":"as-built"}`)
	if code != http.StatusOK {
		t.Fatalf("POST /reset = %d (%s)", code, body)
	}
	var ack Ack
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	res, _ := ack.Result.(map[string]any)
	if res["baseline"] != "as-built" {
		t.Errorf("result.baseline = %v, want as-built (%s)", res["baseline"], body)
	}

	// An EMPTY body is a valid request — "the default baseline" — not a
	// malformed one.
	if code, body := r.post(t, "/reset", ``); code != http.StatusOK {
		t.Fatalf("POST /reset with an empty body = %d (%s), want 200", code, body)
	}
	if code, _ := r.post(t, "/reset", `{"baseline":"nope"}`); code != http.StatusBadRequest {
		t.Fatalf("an unknown baseline answered %d, want 400", code)
	}
}

// TestLedgerQueryParsing: a mistyped fence must be refused, never silently
// read as "everything".
func TestLedgerQueryParsing(t *testing.T) {
	r := newRig(t)
	var got LedgerQuery
	r.srv.SetLedgerFn(func(_ context.Context, q LedgerQuery) (any, error) {
		got = q
		return map[string]any{"entries": []any{}}, nil
	})

	if code, _ := r.get(t, "/ledger?since_epoch=12&since_seq=34&limit=5"); code != http.StatusOK {
		t.Fatalf("GET /ledger = %d", code)
	}
	if got.SinceEpoch != 12 || got.SinceSeq != 34 || got.Limit != 5 {
		t.Fatalf("parsed %+v, want {12 34 5}", got)
	}

	// No parameters means no fence, which is a legitimate request.
	got = LedgerQuery{}
	if code, _ := r.get(t, "/ledger"); code != http.StatusOK {
		t.Fatal("GET /ledger with no parameters was refused")
	}
	if got != (LedgerQuery{}) {
		t.Fatalf("parsed %+v from an empty query, want the zero value", got)
	}

	for _, bad := range []string{"?since_epoch=twelve", "?since_seq=-1", "?limit=x", "?min_entries=n"} {
		code, body := r.get(t, "/ledger"+bad)
		if code != http.StatusBadRequest {
			t.Errorf("GET /ledger%s = %d, want 400 — a fence that silently became 'everything' would "+
				"hand a row the previous test case's transactions", bad, code)
		}
		if !strings.Contains(string(body), "integer") {
			t.Errorf("GET /ledger%s said %q, want a reason", bad, body)
		}
	}
}

// TestLedgerMinEntriesBoundsItselfAndAnswers200 is the ledger's own barrier: a
// row whose provocation prevents a poll cycle from completing still needs to
// know whether the client issued a request under its fence.
func TestLedgerMinEntriesBoundsItselfAndAnswers200(t *testing.T) {
	r := newRig(t)
	var sawMin int
	r.srv.SetLedgerFn(func(ctx context.Context, q LedgerQuery) (any, error) {
		sawMin = q.MinEntries
		if q.MinEntries > 0 {
			<-ctx.Done() // nothing ever matches
		}
		return map[string]any{"entries": []any{}, "total": 0}, nil
	})

	start := time.Now()
	code, body := r.get(t, "/ledger?since_epoch=5&min_entries=1&timeout=120ms")
	if code != http.StatusOK {
		t.Fatalf("GET /ledger?min_entries= = %d (%s), want 200 — 'the client has not asked yet' is an "+
			"observation, not an endpoint failure", code, body)
	}
	if sawMin != 1 {
		t.Fatalf("min_entries reached the handler as %d, want 1", sawMin)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 5*time.Second {
		t.Fatalf("the request took %s; it must honour its own 120ms timeout", d)
	}

	// Without min_entries the request must NOT block, and must not install a
	// deadline the handler could mistake for one.
	r.srv.SetLedgerFn(func(ctx context.Context, q LedgerQuery) (any, error) {
		if _, has := ctx.Deadline(); has {
			t.Error("a plain GET /ledger installed a deadline; only the min_entries form bounds itself")
		}
		return map[string]any{"entries": []any{}}, nil
	})
	start = time.Now()
	if code, _ := r.get(t, "/ledger?since_epoch=5"); code != http.StatusOK {
		t.Fatal("a plain GET /ledger was refused")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a plain GET /ledger took %s; it must not block", d)
	}
}

// TestPollWaitBoundsItselfAndAnswers200: the caller's HTTP timeout must never
// be the thing that decides a verdict.
func TestPollWaitBoundsItselfAndAnswers200(t *testing.T) {
	r := newRig(t)
	r.srv.SetPollFn(func(ctx context.Context, want uint64) (any, error) {
		<-ctx.Done() // never satisfied: the client has not polled
		return map[string]any{"reached": false, "want": want}, nil
	})

	start := time.Now()
	code, body := r.get(t, "/poll/wait?epoch=3&timeout=120ms")
	if code != http.StatusOK {
		t.Fatalf("GET /poll/wait = %d (%s), want 200 — 'the client has not polled yet' is an "+
			"observation, not an endpoint failure", code, body)
	}
	if !strings.Contains(string(body), `"reached":false`) {
		t.Fatalf("body %q does not report reached=false", body)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 5*time.Second {
		t.Fatalf("the request took %s; it must honour its own 120ms timeout", d)
	}
}

// TestPollWaitAcceptsBothSpellingsAndRejectsZero. Two counters in this API are
// called "epoch" somewhere — the control-plane one and the poll-cycle ordinal —
// so both spellings are accepted here and the ambiguity is documented rather
// than left as a trap.
func TestPollWaitAcceptsBothSpellingsAndRejectsZero(t *testing.T) {
	r := newRig(t)
	var seen uint64
	r.srv.SetPollFn(func(_ context.Context, want uint64) (any, error) {
		seen = want
		return map[string]any{"reached": true}, nil
	})

	if code, _ := r.get(t, "/poll/wait?poll=9&timeout=1s"); code != http.StatusOK {
		t.Fatal("GET /poll/wait?poll=… was refused")
	}
	if seen != 9 {
		t.Fatalf("want = %d from ?poll=9", seen)
	}
	if code, _ := r.get(t, "/poll/wait?epoch=4&timeout=1s"); code != http.StatusOK {
		t.Fatal("GET /poll/wait?epoch=… was refused")
	}
	if seen != 4 {
		t.Fatalf("want = %d from ?epoch=4", seen)
	}

	code, body := r.get(t, "/poll/wait?epoch=0")
	if code != http.StatusBadRequest {
		t.Errorf("GET /poll/wait?epoch=0 = %d, want 400", code)
	}
	if !strings.Contains(string(body), "already completed") {
		t.Errorf("the refusal %q does not explain why 0 is meaningless", body)
	}

	for _, bad := range []string{"timeout=0s", "timeout=frog", "timeout=-1"} {
		if code, _ := r.get(t, "/poll/wait?epoch=1&"+bad); code != http.StatusBadRequest {
			t.Errorf("GET /poll/wait?%s = %d, want 400", bad, code)
		}
	}
	// A bare number is seconds, so `timeout=1` and `timeout=1s` agree rather
	// than one of them being a silent misreading of the other.
	if code, _ := r.get(t, "/poll/wait?epoch=1&timeout=1"); code != http.StatusOK {
		t.Error("GET /poll/wait?timeout=1 was refused; a bare number must be read as seconds")
	}
}

// TestPollPlainDoesNotBlock: GET /poll answers now, whatever the client is
// doing.
func TestPollPlainDoesNotBlock(t *testing.T) {
	r := newRig(t)
	r.srv.SetPollFn(func(ctx context.Context, want uint64) (any, error) {
		if want != 0 {
			t.Errorf("GET /poll passed want=%d, want 0", want)
		}
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			t.Error("GET /poll installed a deadline; only /poll/wait bounds itself")
		}
		return map[string]any{"reached": true, "want": want}, nil
	})
	start := time.Now()
	if code, _ := r.get(t, "/poll"); code != http.StatusOK {
		t.Fatal("GET /poll was refused")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("GET /poll took %s; it must not block", d)
	}
}

// TestPollWaitCancelsWhenTheCallerGoesAway: an abandoned request must free its
// goroutine immediately rather than hold it for the rest of the timeout.
func TestPollWaitCancelsWhenTheCallerGoesAway(t *testing.T) {
	r := newRig(t)
	released := make(chan struct{}, 1)
	r.srv.SetPollFn(func(ctx context.Context, _ uint64) (any, error) {
		<-ctx.Done()
		released <- struct{}{}
		return map[string]any{"reached": false}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/poll/wait?epoch=1&timeout=4m", nil)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was still blocked 5s after the caller went away; it must follow the " +
			"request context, not only its own timeout")
	}
}

// TestMethodDiscipline — the deterministic endpoints are as strict about
// method as the rest of the surface.
func TestMethodDiscipline(t *testing.T) {
	r := newRig(t)
	r.srv.SetResetFn(func([]byte) (any, error) { return nil, nil })
	r.srv.SetLedgerFn(func(context.Context, LedgerQuery) (any, error) { return nil, nil })
	r.srv.SetPollFn(func(context.Context, uint64) (any, error) { return nil, nil })

	if code, _ := r.get(t, "/reset"); code != http.StatusMethodNotAllowed {
		t.Errorf("GET /reset = %d, want 405", code)
	}
	for _, p := range []string{"/ledger", "/poll", "/poll/wait", "/version"} {
		if code, _ := r.post(t, p, "{}"); code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", p, code)
		}
	}
}
