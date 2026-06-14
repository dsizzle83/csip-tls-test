package simapi

import (
	"context"
	"fmt"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogBuffer_WriteSplitsLines(t *testing.T) {
	lb := NewLogBuffer()
	// Partial write followed by completion — must yield exactly two lines.
	fmt.Fprintf(lb, "first li")
	fmt.Fprintf(lb, "ne\nsecond line\npart")
	lb.mu.Lock()
	got := append([]string(nil), lb.lines...)
	partial := string(lb.partial)
	lb.mu.Unlock()
	if len(got) != 2 || got[0] != "first line" || got[1] != "second line" {
		t.Fatalf("lines = %q, want [first line, second line]", got)
	}
	if partial != "part" {
		t.Fatalf("partial = %q, want \"part\"", partial)
	}
}

func TestLogBuffer_RingCap(t *testing.T) {
	lb := NewLogBuffer()
	for i := 0; i < maxLogLines+50; i++ {
		fmt.Fprintf(lb, "line %d\n", i)
	}
	lb.mu.Lock()
	n := len(lb.lines)
	first := lb.lines[0]
	lb.mu.Unlock()
	if n != maxLogLines {
		t.Fatalf("ring holds %d lines, want %d", n, maxLogLines)
	}
	if first != "line 50" {
		t.Fatalf("oldest retained = %q, want \"line 50\"", first)
	}
}

// TestLogBuffer_SSE verifies the /logs handler replays the backlog and
// streams new lines in lexa-api-compatible SSE framing, including lines
// teed from the standard logger.
func TestLogBuffer_SSE(t *testing.T) {
	lb := NewLogBuffer()

	// Backlog via a teed standard logger.
	logger := log.New(lb, "", 0)
	logger.Printf("backlog entry")

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/logs", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		lb.ServeHTTP(rec, req)
	}()

	// Send a live line after subscribe. Give the handler a moment to drain
	// its channel, then hang up; the body is only read once the handler has
	// returned (httptest.ResponseRecorder is not safe for concurrent reads).
	logger.Printf("live entry")
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "data: backlog entry\n\n") {
		t.Errorf("backlog not replayed; body: %q", body)
	}
	if !strings.Contains(body, "data: live entry\n\n") {
		t.Errorf("live line not streamed; body: %q", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
}
