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
	"fmt"
	"io"
	"net/http"
	"sync"
)

// maxLogLines bounds the replay backlog kept per simulator.
const maxLogLines = 400

// LogBuffer is a goroutine-safe ring of recent log lines with subscriber
// fan-out. The zero value is not usable; create with NewLogBuffer.
type LogBuffer struct {
	mu      sync.Mutex
	lines   []string // ring: oldest first, capped at maxLogLines
	subs    map[chan string]struct{}
	partial []byte // trailing bytes of an incomplete line from Write
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
		lb.lines = lb.lines[len(lb.lines)-maxLogLines:]
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
