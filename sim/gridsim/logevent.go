package gridsim

// logevent.go — the server half of the IEEE 2030.5 Log Event function set
// (§11.4 / BASIC-027, WP-6). The EndDevice advertises a LogEventListLink
// (/edev/2/lev); lexa-northbound POSTs a LogEvent per locally generated DER
// alarm (and its return-to-normal). gridsim answers 201 + Location, appends to
// a time-ordered list served at GET /edev/2/lev, and exposes the list for
// test/bench assertion via GET /admin/logevents.
//
// Additive and always-on: it only adds a POST target + a GET resource that did
// not exist before, so no existing discovery/telemetry path changes.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	model "lexa-proto/csipmodel"
)

// isLogEventListPath reports whether path is an EndDevice's LogEventList
// endpoint (…/lev). Matching on gridsim's own advertised suffix keeps the POST
// router in step with the LogEventListLink the tree serves.
func isLogEventListPath(path string) bool {
	return strings.HasPrefix(path, "/edev/") && strings.HasSuffix(path, "/lev")
}

// handleLogEventPost accepts POST {…/lev} with a LogEvent body. A well-formed,
// correctly-namespaced LogEvent is appended and answered 201 + Location
// (…/lev/{n}); garbage is 400.
func (s *Server) handleLogEventPost(w http.ResponseWriter, r *http.Request, path, peerLFDI string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var ev model.LogEvent
	if err := xml.Unmarshal(body, &ev); err != nil {
		log.Printf("[gridsim] POST %s: unmarshal LogEvent error: %v", path, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.logEventMu.Lock()
	id := s.logEventNextID
	s.logEventNextID++
	location := fmt.Sprintf("%s/%d", path, id)
	ev.Href = location
	if ev.CreatedDateTime == 0 {
		ev.CreatedDateTime = s.Now()
	}
	s.logEvents = append(s.logEvents, ev)
	s.logEventMu.Unlock()

	// Reflect the new event into the served LogEventList so a subsequent GET
	// (and the advertised all/results counts) matches what was POSTed, and
	// store the individual event for GET …/lev/{n} (mirrors the MUP flow).
	s.mu.Lock()
	if lel, ok := s.resources[stripLastSegment(location)].(*model.LogEventList); ok {
		lel.LogEvent = append(lel.LogEvent, ev)
		lel.All = uint32(len(lel.LogEvent))
		lel.Results = lel.All
	}
	s.resources[location] = &ev
	s.mu.Unlock()

	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
	log.Printf("[gridsim] POST %s → LogEvent stored at %s (funcSet=%d code=%d peer=%s)",
		path, location, ev.FunctionSet, ev.LogEventCode, peerLFDI)
}

// stripLastSegment returns path with its final "/segment" removed
// (…/lev/3 → …/lev).
func stripLastSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return path
}

// ReceivedLogEvents returns a copy of all LogEvents POSTed by clients, in
// arrival order. Useful for verifying WP-6 LogEvent reporting in tests.
func (s *Server) ReceivedLogEvents() []model.LogEvent {
	s.logEventMu.Lock()
	defer s.logEventMu.Unlock()
	out := make([]model.LogEvent, len(s.logEvents))
	copy(out, s.logEvents)
	return out
}

// handleAdminLogEvents serves GET /admin/logevents — the received LogEvents in
// arrival order.
func (s *Server) handleAdminLogEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	events := s.ReceivedLogEvents()
	if events == nil {
		events = []model.LogEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"log_events":  events,
		"server_time": s.Now(),
	})
}
