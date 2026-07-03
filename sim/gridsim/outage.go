package gridsim

// outage.go — northbound-outage injection for QA (POST /admin/outage).
//
// A DERMS hub's WAN link to the utility server drops all the time in the
// field: backhaul flaps, the head-end reboots, a middlebox wedges half-open
// connections. This injector makes the CSIP-served tree (the mTLS side)
// misbehave while the admin API stays reachable, so the Mayhem driver can
// keep observing and tearing down. Two failure shapes, matching the two ways
// a hub's fetcher can suffer:
//
//	"down" — every CSIP request is answered 503 immediately. Models a dead or
//	         rebooting head-end: the walk fails FAST and the hub must fall
//	         back to its last-known-good controls.
//	"hang" — every CSIP request stalls hangS seconds before the 503. Models a
//	         wedged server / black-holing middlebox: the walk fails SLOW, and
//	         a fetcher without its own deadline wedges the whole northbound.
//
// The gate sits in handleRequest, which runs over the wolfSSL bridge's custom
// HTTP loop (sim/tlsserver/handlers.go) — no panics, no connection hijacking:
// only well-formed slow/error responses, which is also all a real broken
// server can produce once TLS is up. duration_s auto-clears the outage so an
// aborted QA run can never leave the bench northbound-dead.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Supported outage modes.
const (
	OutageDown = "down" // immediate 503 on every CSIP request
	OutageHang = "hang" // stall hangS, then 503
)

// outageDefaultHangS is the per-request stall for mode "hang" when the arm
// request does not specify one. Longer than any sane client deadline, short
// enough that stalled handler goroutines drain soon after the outage clears.
const outageDefaultHangS = 30

// SetOutage arms (mode != "") or clears (mode == "") the northbound outage.
// durationS > 0 auto-clears after that many seconds; hangS configures the
// "hang" stall (0 ⇒ outageDefaultHangS).
func (s *Server) SetOutage(mode string, durationS, hangS int) error {
	if mode != "" && mode != OutageDown && mode != OutageHang {
		return fmt.Errorf("unknown outage mode %q", mode)
	}
	if hangS <= 0 {
		hangS = outageDefaultHangS
	}
	s.mu.Lock()
	s.outageMode = mode
	s.outageHangS = hangS
	s.outageSeq++
	seq := s.outageSeq
	s.mu.Unlock()

	if mode != "" && durationS > 0 {
		time.AfterFunc(time.Duration(durationS)*time.Second, func() {
			s.mu.Lock()
			// Only clear if no newer arm/clear superseded this one.
			if s.outageSeq == seq {
				s.outageMode = ""
			}
			s.mu.Unlock()
		})
	}
	return nil
}

// handleAdminOutage is POST /admin/outage {"mode":"down|hang","duration_s":N,"hang_s":N,"clear":bool}.
func (s *Server) handleAdminOutage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Mode      string `json:"mode"`
		DurationS int    `json:"duration_s"`
		HangS     int    `json:"hang_s"`
		Clear     bool   `json:"clear"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	mode := req.Mode
	if req.Clear {
		mode = ""
	}
	if err := s.SetOutage(mode, req.DurationS, req.HangS); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// outageIntercept applies the armed outage to a CSIP request about to be
// served. Returns true when it wrote the (failure) response itself.
func (s *Server) outageIntercept(w http.ResponseWriter) bool {
	s.mu.RLock()
	mode, hangS := s.outageMode, s.outageHangS
	s.mu.RUnlock()
	switch mode {
	case OutageDown:
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	case OutageHang:
		time.Sleep(time.Duration(hangS) * time.Second)
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	return false
}
