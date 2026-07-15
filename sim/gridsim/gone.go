package gridsim

// gone.go — resource_410 injection (QA fault mode, default OFF).
//
// When armed (POST /admin/gone), GETs of a configured path answer 410 Gone
// instead of the resource, so the hub's fail-closed "hold last-known-good on a
// gone resource" path (internal/northbound rule 6) can be exercised on the
// wire. A 410 is a stronger signal than the 503 /admin/outage serves — it
// says the resource is PERMANENTLY gone, not merely unavailable — so a hub
// that special-cases 410 as "this resource was deleted, drop my state" (a
// fail-open bug) is caught here where a 503 would not.
//
// Modeled on redirect.go's redirectIntercept: an above-routing intercept that
// fires before any resource lookup or LFDI gating. Default behaviour is
// unchanged — with remaining == 0 the intercept is a cheap no-op and every GET
// serves as before.

import (
	"encoding/json"
	"log"
	"net/http"
)

// goneState is the armed 410-injection configuration. Zero value
// (remaining == 0) means disarmed.
type goneState struct {
	path      string // GET path that answers 410 (e.g. "/dcap" or "/derp/0/derc")
	remaining int    // GETs left to 410; 0 ⇒ disarmed, <0 ⇒ unlimited (until cleared)
}

// goneIntercept answers a matching GET with 410 Gone while the mode is armed.
// Returns true if it wrote the 410 (the caller must then stop). A positive
// remaining counts down (like redirect's per-hit budget — "N gones then it
// serves again"); a negative remaining stays gone until explicitly cleared,
// which is what a scenario arms so the resource is gone for every walk across
// its whole hold.
func (s *Server) goneIntercept(w http.ResponseWriter, path string) bool {
	s.goneMu.Lock()
	st := s.gone
	armed := st.remaining != 0 && path == st.path
	if armed && s.gone.remaining > 0 {
		s.gone.remaining--
	}
	s.goneMu.Unlock()

	if !armed {
		return false
	}
	w.WriteHeader(http.StatusGone)
	log.Printf("[gridsim] gone: GET %s → 410 (remaining=%d)", path, st.remaining)
	return true
}

// SetGone arms (count != 0) or disarms (count == 0) 410 injection for path.
// path defaults to /dcap. count > 0 answers that many GETs with 410 then heals;
// count < 0 stays gone until cleared.
func (s *Server) SetGone(path string, count int) {
	if count == 0 {
		s.goneMu.Lock()
		s.gone = goneState{}
		s.goneMu.Unlock()
		return
	}
	if path == "" {
		path = "/dcap"
	}
	s.goneMu.Lock()
	s.gone = goneState{path: path, remaining: count}
	s.goneMu.Unlock()
}

// adminGoneReq is the body for POST /admin/gone.
type adminGoneReq struct {
	Path  string `json:"path"`  // default /dcap
	Count int    `json:"count"` // >0 = that many 410s then heal; <0 = until cleared; 0/clear disarms
	Clear bool   `json:"clear"`
}

// handleAdminGone is POST /admin/gone. Arm with
// {"path":"/derp/0/derc","count":-1}; disarm with {"clear":true}.
func (s *Server) handleAdminGone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req adminGoneReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	count := req.Count
	if req.Clear {
		count = 0
	}
	s.SetGone(req.Path, count)
	w.WriteHeader(http.StatusNoContent)
}
