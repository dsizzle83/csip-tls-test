package simapi

// logs.go — bounded in-memory log ring with SSE fan-out.
//
// Each simulator tees its standard logger into a LogBuffer
// (log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))), and the
// dashboard subscribes to GET /logs. The wire contract matches lexa-api's
// /logs endpoint: text/event-stream, one "data: <line>" event per log line,
// with the recent backlog replayed on subscribe so a fresh page fills in
// immediately.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// maxLogLines bounds the replay backlog kept per simulator.
//
// This is a RING: once it is full, old lines are evicted. Any consumer that
// derives "what happened since I last looked" MUST do so from Seq (below) and
// MUST check the reported drop count. Deriving it from len() instead is wrong
// the moment the ring wraps, and wrong in the worst possible direction — see
// the Seq doc.
const maxLogLines = 4000

// LogBuffer is a goroutine-safe ring of recent log lines with subscriber
// fan-out. The zero value is not usable; create with NewLogBuffer.
type LogBuffer struct {
	mu    sync.Mutex
	lines []string // ring: oldest first, capped at maxLogLines
	// firstSeq is the sequence number of lines[0]; it advances as the ring
	// evicts. total lines ever written == firstSeq + len(lines).
	//
	// WHY A SEQUENCE NUMBER EXISTS
	//
	// A reader used to compute its delta as "the entries past the length I saw
	// last time". That is correct only for an unbounded append-only list. On a
	// bounded ring, len() saturates at maxLogLines and STOPS GROWING while
	// events keep arriving, so the computed delta becomes permanently empty.
	//
	// The conformance harness read this buffer that way. Roughly ten minutes
	// into a run — one 2030.5 discovery walk is ~28 logged GETs — the ring
	// wrapped, every subsequent delta came back empty, and 22 test cases
	// reported "the DUT did nothing in this window" about a gateway that was
	// polling perfectly on time. An empty delta is indistinguishable from
	// silence, which is why this failed as false FAILs rather than as an error.
	//
	// Sequence numbers make the delta exact, and Since reports what it had to
	// evict so a truncated view can never be mistaken for a quiet one.
	firstSeq uint64
	subs     map[chan string]struct{}
	partial  []byte // trailing bytes of an incomplete line from Write
}

// LogSlice is a cursor-based read of the ring.
type LogSlice struct {
	// Lines are the entries from the requested cursor onward.
	Lines []string `json:"lines"`
	// Next is the cursor to pass on the following call.
	Next uint64 `json:"next"`
	// Dropped is how many entries were evicted before the requested cursor —
	// i.e. how much the reader missed by not reading sooner. It is NOT
	// advisory: a caller that ignores it is back to mistaking truncation for
	// silence.
	Dropped uint64 `json:"dropped"`
}

// Since returns every line with a sequence number >= cursor, the cursor to use
// next, and how many lines were evicted before cursor could be served.
//
// Pass cursor 0 for "everything currently retained". The returned Next is
// always safe to pass back, including when Dropped is non-zero.
func (lb *LogBuffer) Since(cursor uint64) LogSlice {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	end := lb.firstSeq + uint64(len(lb.lines))
	var dropped uint64
	if cursor < lb.firstSeq {
		dropped = lb.firstSeq - cursor
		cursor = lb.firstSeq
	}
	if cursor > end {
		cursor = end
	}
	out := make([]string, end-cursor)
	copy(out, lb.lines[cursor-lb.firstSeq:])
	return LogSlice{Lines: out, Next: end, Dropped: dropped}
}

// ServeSince is the JSON, cursor-based counterpart to ServeHTTP's SSE stream.
// Programmatic readers use this; the dashboard keeps the stream.
func (lb *LogBuffer) ServeSince(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cursor uint64
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			http.Error(w, "since must be a non-negative integer", http.StatusBadRequest)
			return
		}
		cursor = n
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(lb.Since(cursor))
}

// NewLogBuffer creates an empty LogBuffer.
func NewLogBuffer() *LogBuffer {
	return &LogBuffer{subs: make(map[chan string]struct{})}
}

// Write implements io.Writer so the buffer can tee the standard logger.
// Input is split on newlines; an incomplete trailing line is held until the
// next Write completes it.
func (lb *LogBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	data := append(lb.partial, p...)
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			break
		}
		lb.appendLocked(string(data[:idx]))
		data = data[idx+1:]
	}
	lb.partial = append(lb.partial[:0], data...)
	return len(p), nil
}

// appendLocked stores one line and notifies subscribers. Caller holds lb.mu.
func (lb *LogBuffer) appendLocked(line string) {
	if line == "" {
		return
	}
	lb.lines = append(lb.lines, line)
	if len(lb.lines) > maxLogLines {
		drop := len(lb.lines) - maxLogLines
		lb.lines = lb.lines[drop:]
		lb.firstSeq += uint64(drop) // keep firstSeq the sequence of lines[0]
	}
	for ch := range lb.subs {
		select {
		case ch <- line:
		default: // slow subscriber: drop rather than block the logger
		}
	}
}

// subscribe registers a new subscriber and returns its channel plus a copy of
// the backlog to replay first.
func (lb *LogBuffer) subscribe() (chan string, []string) {
	ch := make(chan string, 64)
	lb.mu.Lock()
	backlog := make([]string, len(lb.lines))
	copy(backlog, lb.lines)
	lb.subs[ch] = struct{}{}
	lb.mu.Unlock()
	return ch, backlog
}

func (lb *LogBuffer) unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.subs, ch)
	lb.mu.Unlock()
}

// ServeHTTP streams the buffer as text/event-stream (SSE), replaying the
// backlog first. Compatible with the lexa-api /logs format.
func (lb *LogBuffer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, backlog := lb.subscribe()
	defer lb.unsubscribe(ch)
	for _, line := range backlog {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}
}

// LogWriter returns the io.Writer simulators tee their standard logger into:
//
//	log.SetOutput(io.MultiWriter(os.Stderr, api.LogWriter()))
func (s *Server) LogWriter() io.Writer { return s.logBuf }
