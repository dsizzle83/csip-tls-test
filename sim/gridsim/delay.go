package gridsim

// delay.go — event_delay injection (QA fault mode, default OFF).
//
// When armed (POST /admin/delay), GETs of a configured path sleep for a fixed
// delay BEFORE the resource is served (a normal 200 body still follows). This
// exercises the hub's discovery timeout / hang tolerance WITHOUT a full outage:
// the resource is still there and still correct, it just arrives slowly, so a
// hub whose fetcher has no per-request deadline wedges while a hub that bounds
// its reads either completes the slow walk or times out and holds
// last-known-good.
//
// This is the "slow but eventually-successful response" companion to
// outage.go's "down" (immediate 503) and "hang" (stall-then-503): here the
// stall is followed by the REAL resource. Because the delay happens inside the
// handler before it returns, it works identically over the buffered wolfSSL
// bridge (sim/tlsserver) and a plain net/http server.
//
// duration_s auto-clears the delay (like outage) so an aborted QA run can
// never leave the bench northbound permanently slow. Default behaviour is
// unchanged — with delay == 0 the intercept is a cheap no-op.

import (
	"encoding/json"
	"net/http"
	"time"
)

// delayState is the armed per-path delay. Zero value (delay == 0) is disarmed.
type delayState struct {
	path  string        // GET path to delay; "" ⇒ all GET paths
	delay time.Duration // per-request stall before serving
}

// SetDelay arms (delayMs > 0) or clears (delayMs <= 0) the per-path response
// delay. path == "" delays every GET. durationS > 0 auto-clears after that many
// seconds.
func (s *Server) SetDelay(path string, delayMs, durationS int) {
	s.delayMu.Lock()
	if delayMs <= 0 {
		s.delay = delayState{}
	} else {
		s.delay = delayState{path: path, delay: time.Duration(delayMs) * time.Millisecond}
	}
	s.delaySeq++
	seq := s.delaySeq
	s.delayMu.Unlock()

	if delayMs > 0 && durationS > 0 {
		time.AfterFunc(time.Duration(durationS)*time.Second, func() {
			s.delayMu.Lock()
			// Only clear if no newer arm/clear superseded this one.
			if s.delaySeq == seq {
				s.delay = delayState{}
			}
			s.delayMu.Unlock()
		})
	}
}

// delayIntercept stalls a matching GET for the armed delay, then returns so the
// caller serves the resource normally. It never writes a response itself (the
// resource still gets served) — unlike gone/redirect/outage it is a pure stall.
// The sleep runs OUTSIDE the lock, matching outageIntercept's "hang".
func (s *Server) delayIntercept(path string) {
	s.delayMu.Lock()
	st := s.delay
	s.delayMu.Unlock()
	if st.delay <= 0 {
		return
	}
	if st.path != "" && st.path != path {
		return
	}
	time.Sleep(st.delay)
}

// adminDelayReq is the body for POST /admin/delay.
type adminDelayReq struct {
	Path      string `json:"path"`       // "" = all GET paths
	DelayMs   int    `json:"delay_ms"`   // per-request stall in milliseconds; 0/clear disarms
	DurationS int    `json:"duration_s"` // auto-clear after N seconds (0 = no auto-clear)
	Clear     bool   `json:"clear"`
}

// handleAdminDelay is POST /admin/delay. Arm with
// {"path":"/dcap","delay_ms":20000,"duration_s":90}; disarm with {"clear":true}.
func (s *Server) handleAdminDelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req adminDelayReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	delayMs := req.DelayMs
	if req.Clear {
		delayMs = 0
	}
	s.SetDelay(req.Path, delayMs, req.DurationS)
	w.WriteHeader(http.StatusNoContent)
}
