package main

// logmux.go — server-side merge of all backend /logs SSE streams into one.
//
// Browsers cap concurrent HTTP/1.1 connections per host (~6), so the Logs tab
// cannot open one EventSource per backend without starving the dashboard's
// polling fetches. Instead the dashboard server follows each backend's SSE
// stream itself (no browser limits server-side) and re-publishes everything on
// a single endpoint:
//
//	GET /api/logs/all — SSE; each event's data is {"src","line","at"} JSON.
//
// A bounded ring is replayed to new subscribers so a fresh page fills in
// immediately. Backend connections retry forever with a fixed backoff; a
// backend replaying its own backlog after a reconnect can introduce duplicate
// lines, which is accepted for a lab tool.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	logMuxRingSize  = 800
	logMuxRetryWait = 5 * time.Second
)

type logEvent struct {
	Src  string    `json:"src"`
	Line string    `json:"line"`
	At   time.Time `json:"at"`
}

type logMux struct {
	mu   sync.Mutex
	ring []logEvent
	subs map[chan logEvent]struct{}
}

// newLogMux starts one follower goroutine per backend (src → SSE URL) and
// returns the merged-stream handler.
func newLogMux(backends map[string]string) *logMux {
	m := &logMux{subs: make(map[chan logEvent]struct{})}
	for src, url := range backends {
		go m.follow(src, url)
	}
	return m
}

func (m *logMux) follow(src, url string) {
	for {
		if err := m.streamOnce(src, url); err != nil {
			log.Printf("dashboard: logmux %s (%s): %v — retrying in %s", src, url, err, logMuxRetryWait)
		}
		time.Sleep(logMuxRetryWait)
	}
}

// streamOnce connects to one backend /logs SSE stream and publishes every
// data line until the connection drops.
func (m *logMux) streamOnce(src, url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// TASK-014: the hub's /logs requires the bearer token once lexa-api has
	// one configured; setHubAuth is a no-op for every other src.
	setHubAuth(req, src)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		line := sc.Text()
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			m.publish(logEvent{Src: src, Line: data, At: time.Now()})
		}
	}
	return sc.Err()
}

func (m *logMux) publish(ev logEvent) {
	m.mu.Lock()
	m.ring = append(m.ring, ev)
	if len(m.ring) > logMuxRingSize {
		m.ring = m.ring[len(m.ring)-logMuxRingSize:]
	}
	for ch := range m.subs {
		select {
		case ch <- ev:
		default: // drop for slow subscribers rather than block the follower
		}
	}
	m.mu.Unlock()
}

func (m *logMux) subscribe() (chan logEvent, []logEvent) {
	ch := make(chan logEvent, 128)
	m.mu.Lock()
	backlog := make([]logEvent, len(m.ring))
	copy(backlog, m.ring)
	m.subs[ch] = struct{}{}
	m.mu.Unlock()
	return ch, backlog
}

func (m *logMux) unsubscribe(ch chan logEvent) {
	m.mu.Lock()
	delete(m.subs, ch)
	m.mu.Unlock()
}

// ServeHTTP streams the merged log as SSE with JSON event payloads.
func (m *logMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func(ev logEvent) bool {
		b, err := json.Marshal(ev)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		return true
	}

	ch, backlog := m.subscribe()
	defer m.unsubscribe(ch)
	for _, ev := range backlog {
		if !send(ev) {
			return
		}
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if !send(ev) {
				return
			}
			flusher.Flush()
		}
	}
}
