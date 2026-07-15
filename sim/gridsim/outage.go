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
	OutageSlow = "slow" // slow-loris: trickle a 200 body byte-slow over hangS
)

// outageDefaultHangS is the per-request stall for mode "hang" (and the total
// drip budget for mode "slow") when the arm request does not specify one.
// Longer than any sane client deadline, short enough that stalled handler
// goroutines drain soon after the outage clears.
const outageDefaultHangS = 30

// outageSlowChunks is how many pieces mode "slow" splits its trickled body
// into, sleeping hangS/outageSlowChunks between each. Enough pieces that the
// inter-write gap is a meaningful fraction of a client's read deadline.
const outageSlowChunks = 12

// outageSlowBody is the benign sep+xml payload mode "slow" trickles. Its
// CONTENT is immaterial — the fault is the timing (a client with a per-read
// deadline shorter than the inter-chunk gap must time out) — but keeping it a
// well-formed fragment means a client that DOES read to the end gets parseable
// bytes rather than garbage that might trip an unrelated code path.
var outageSlowBody = []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
	`<!-- gridsim slow-loris: this response body is being trickled byte-slow to exercise the client read deadline (QA fault mode OutageSlow) -->` + "\n")

// SetOutage arms (mode != "") or clears (mode == "") the northbound outage.
// durationS > 0 auto-clears after that many seconds; hangS configures the
// "hang" stall / "slow" drip budget (0 ⇒ outageDefaultHangS).
func (s *Server) SetOutage(mode string, durationS, hangS int) error {
	if mode != "" && mode != OutageDown && mode != OutageHang && mode != OutageSlow {
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
	case OutageSlow:
		s.trickleBody(w, hangS)
		return true
	}
	return false
}

// trickleBody drip-feeds a 200 response body over totalS seconds — a
// slow-loris: enough dead air between writes to trip a client read deadline.
//
// Over a streaming ResponseWriter (a plain net/http server, e.g. the Go
// integration tests) this genuinely trickles: each Flush pushes a chunk onto
// the wire, so a client reading with a per-read deadline shorter than the
// inter-chunk gap times out mid-body. Over the buffered wolfSSL bridge
// (sim/tlsserver's bufferedResponseWriter captures the whole response and
// writes it in one shot after the handler returns, and does not implement
// http.Flusher) the Flush is a no-op and the trickle degrades to a single
// write delayed by the full drip budget — which still exercises the client's
// TOTAL-response deadline, just not the per-read one. Both are honest models
// of a sick server; the bridge limitation is why this lives here and not in a
// hijack-the-conn path (outage.go's package doc: no connection hijacking).
func (s *Server) trickleBody(w http.ResponseWriter, totalS int) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	body := outageSlowBody
	chunkLen := (len(body) + outageSlowChunks - 1) / outageSlowChunks
	if chunkLen < 1 {
		chunkLen = 1
	}
	var chunks [][]byte
	for off := 0; off < len(body); off += chunkLen {
		end := off + chunkLen
		if end > len(body) {
			end = len(body)
		}
		chunks = append(chunks, body[off:end])
	}
	per := time.Duration(totalS) * time.Second / time.Duration(len(chunks))
	for _, c := range chunks {
		_, _ = w.Write(c)
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(per)
	}
}
