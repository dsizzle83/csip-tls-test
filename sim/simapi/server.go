// Package simapi provides a lightweight HTTP + WebSocket API server that
// each simulator binary embeds. It exposes simulator state for GUI consumption
// and accepts injection/control commands from a Python GUI or any HTTP client.
//
// Endpoints:
//
//	GET  /version  — this API's version and the endpoints this sim implements
//	GET  /state    — JSON snapshot of current simulator state (decoded values)
//	POST /inject   — inject field overrides; body: {"W_W": 4500.0, ...}
//	POST /control  — animation control; body: {"cmd":"pause"|"resume"|"reset", "speed":N}
//	POST /fault    — arm/clear a fault injector; body: {"kind":"ack_before_effect","delay_s":30}
//	POST /reset    — restore a named baseline register image; body: {"baseline":"as-built"}
//	GET  /registers — raw Modbus register dump (Modbus sims only; 404 if unsupported)
//	GET  /ledger   — the sim's own append-only Modbus transaction record
//	GET  /poll     — the client's poll-cycle accounting, as the sim counts it
//	GET  /poll/wait — block until a given poll cycle has completed
//	GET  /ws       — WebSocket: pushes /state JSON every 2 seconds
//	GET  /logs     — SSE stream of the simulator's log lines (backlog replayed)
//
// All endpoints add Access-Control-Allow-Origin: * so a browser-based GUI
// running on a desktop can talk to a Pi simulator without a proxy.
//
// # The epoch, and why the mutating endpoints answer with a body
//
// /inject, /control, /fault and /reset each acknowledge with
// {"api_version":"…","epoch":N} when the sim has registered an epoch counter,
// and with the historic 204 No Content when it has not. N is the sim's
// CONTROL-PLANE STATE VERSION after the change: the fence a caller passes to
// GET /ledger?since_epoch=N to select exactly the transactions its own
// provocation could have touched. See sim/southbound/epoch.go for what does
// and does not move it — deliberately, the free-running animation does not.
//
// The change is backward compatible by construction: a 200 with a JSON body is
// as acceptable to every existing caller as the 204 was (the harness's
// SimClient decodes into a nil destination and ignores it), and a sim that
// registers no epoch counter is byte-identical to before.
package simapi

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// StateFunc returns the current simulator state as a JSON-serializable value.
// Called on every GET /state request and every WebSocket broadcast tick.
type StateFunc func() any

// InjectFunc applies a raw JSON body to the simulator, overriding one or more
// field values. Return a non-nil error to send a 400 response to the caller.
// May be nil to disable POST /inject.
type InjectFunc func(body []byte) error

// RegistersFunc returns a raw register dump. May be nil to disable GET /registers.
type RegistersFunc func() any

// ControlCmd is the parsed body for POST /control.
type ControlCmd struct {
	Cmd   string  `json:"cmd"`   // "pause" | "resume" | "reset"
	Speed float64 `json:"speed"` // animation speed multiplier (0 = unchanged)

	// ReversionScale multiplies the rate of the DEVICE-SIDE REVERSION CLOCK —
	// the clock a SunSpec reversion timer (704 *RvrtTms, 705/706/711/712
	// RvrtTms, 123's four, the 12x family's) counts down against. 0 leaves it
	// unchanged, matching Speed's convention, so a body sent for any other
	// purpose cannot reset it; 1 is real time; N > 0 is N× acceleration.
	//
	// It is DELIBERATELY SEPARATE FROM Speed. Speed scales the animation — the
	// irradiance model, the measurements, the physics — and a reversion timer
	// is not part of the animation; it is the device's dead-man switch, and it
	// keeps running while the animation is paused. Folding the two together
	// would make "run the weather faster" silently expire live controls.
	//
	// A simulator that has no reversion engine REFUSES a non-zero value rather
	// than ignoring it, so a bench that asked for acceleration and did not get
	// it finds out at the request instead of at the end of the row. See
	// sim/southbound/reversion.go for what an accelerated run does and does not
	// establish.
	ReversionScale float64 `json:"reversion_scale"`
}

// ControlFunc applies a control command to the simulator.
// May be nil to disable POST /control.
type ControlFunc func(cmd ControlCmd) error

// ResetFunc restores a named baseline from the raw POST /reset body and
// returns whatever the sim wants to report about what it did (the baseline
// applied, the clear-up steps it ran). Registered via SetResetFn; nil (the
// default) makes POST /reset return 501.
type ResetFunc func(body []byte) (any, error)

// LedgerFunc answers GET /ledger for a parsed query. Registered via
// SetLedgerFn; nil makes the endpoint return 501.
type LedgerFunc func(q LedgerQuery) (any, error)

// LedgerQuery is GET /ledger's parsed query string.
type LedgerQuery struct {
	// SinceEpoch keeps transactions stamped at or after this control-plane
	// epoch — the fence form, and the reason the mutating endpoints hand an
	// epoch back.
	SinceEpoch uint64
	// SinceSeq keeps transactions after this ledger sequence number — the
	// paging form.
	SinceSeq uint64
	// Limit caps the number of entries returned; 0 means no cap.
	Limit int
}

// PollFunc answers GET /poll (want == 0, non-blocking) and GET /poll/wait
// (want > 0, blocking until that many cycles have completed or ctx is done).
// It must never block on a timer of its own. Registered via SetPollFn; nil
// makes both endpoints return 501.
type PollFunc func(ctx context.Context, want uint64) (any, error)

// EpochFunc advances the sim's control-plane state version and returns the new
// value. The server calls it exactly once after each ACCEPTED mutation, so one
// bump corresponds to one request a caller issued. Registered via SetEpochFn;
// nil (the default) keeps the historic 204 No Content acknowledgements.
type EpochFunc func() uint64

// FaultFunc arms or clears a fault injector from the raw POST /fault body.
// Each sim parses the body (a sim.FaultSpec) and applies the kinds it
// supports, returning an error (→ 400) for unsupported kinds or bad params.
// Registered via SetFaultFn; nil (the default) makes POST /fault return 501.
type FaultFunc func(body []byte) error

// Server is the HTTP + WebSocket API server embedded by each simulator binary.
type Server struct {
	stateFn     StateFunc
	injectFn    InjectFunc
	registersFn RegistersFunc
	controlFn   ControlFunc
	logBuf      *LogBuffer

	mu       sync.Mutex
	clients  map[chan []byte]struct{}
	faultFn  FaultFunc  // guarded by mu; set via SetFaultFn, may be nil
	resetFn  ResetFunc  // guarded by mu; set via SetResetFn, may be nil
	ledgerFn LedgerFunc // guarded by mu; set via SetLedgerFn, may be nil
	pollFn   PollFunc   // guarded by mu; set via SetPollFn, may be nil
	epochFn  EpochFunc  // guarded by mu; set via SetEpochFn, may be nil
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// New creates and starts an API server on addr (e.g. ":6020").
// Non-nil callbacks are wired to their respective endpoints.
func New(addr string, stateFn StateFunc, injectFn InjectFunc, registersFn RegistersFunc, controlFn ControlFunc) *Server {
	s := &Server{
		stateFn:     stateFn,
		injectFn:    injectFn,
		registersFn: registersFn,
		controlFn:   controlFn,
		logBuf:      NewLogBuffer(),
		clients:     make(map[chan []byte]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/state", s.handleState)
	mux.HandleFunc("/reset", s.handleReset)
	mux.HandleFunc("/ledger", s.handleLedger)
	mux.HandleFunc("/poll", s.handlePoll)
	mux.HandleFunc("/poll/wait", s.handlePollWait)
	mux.HandleFunc("/inject", s.handleInject)
	mux.HandleFunc("/control", s.handleControl)
	mux.HandleFunc("/fault", s.handleFault)
	mux.HandleFunc("/registers", s.handleRegisters)
	mux.HandleFunc("/ws", s.handleWS)
	mux.Handle("/logs", s.logBuf)

	go func() {
		log.Printf("[simapi] API server v%s on %s  (GET /state  POST /inject  POST /control  POST /fault  "+
			"POST /reset  GET /registers  GET /ledger  GET /poll[/wait]  GET /ws  GET /logs)", APIVersion, addr)
		if err := http.ListenAndServe(addr, cors(mux)); err != nil {
			log.Printf("[simapi] server error on %s: %v", addr, err)
		}
	}()
	go s.broadcastLoop(2 * time.Second)
	return s
}

// SetFaultFn registers (or replaces) the fault injector handler wired to
// POST /fault. Call it after New, before the sim is driven under test.
func (s *Server) SetFaultFn(fn FaultFunc) {
	s.mu.Lock()
	s.faultFn = fn
	s.mu.Unlock()
}

// SetResetFn registers the baseline-restore handler wired to POST /reset.
func (s *Server) SetResetFn(fn ResetFunc) {
	s.mu.Lock()
	s.resetFn = fn
	s.mu.Unlock()
}

// SetLedgerFn registers the transaction-record handler wired to GET /ledger.
func (s *Server) SetLedgerFn(fn LedgerFunc) {
	s.mu.Lock()
	s.ledgerFn = fn
	s.mu.Unlock()
}

// SetPollFn registers the poll-accounting handler wired to GET /poll and
// GET /poll/wait.
func (s *Server) SetPollFn(fn PollFunc) {
	s.mu.Lock()
	s.pollFn = fn
	s.mu.Unlock()
}

// SetEpochFn registers the control-plane epoch counter. Once registered, every
// accepted mutation acknowledges with {"api_version":…,"epoch":N} instead of
// 204 No Content.
func (s *Server) SetEpochFn(fn EpochFunc) {
	s.mu.Lock()
	s.epochFn = fn
	s.mu.Unlock()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.stateFn())
}

func (s *Server) handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.injectFn == nil {
		http.Error(w, "inject not supported by this simulator", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.injectFn(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.ackMutation(w, nil)
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.controlFn == nil {
		http.Error(w, "control not supported by this simulator", http.StatusNotImplemented)
		return
	}
	var cmd ControlCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.controlFn(cmd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.ackMutation(w, nil)
}

func (s *Server) handleFault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	fn := s.faultFn
	s.mu.Unlock()
	if fn == nil {
		http.Error(w, "fault injection not supported by this simulator", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := fn(body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.ackMutation(w, nil)
}

func (s *Server) handleRegisters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.registersFn == nil {
		http.Error(w, "register dump not supported by this simulator", http.StatusNotImplemented)
		return
	}
	writeJSON(w, s.registersFn())
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[simapi] ws upgrade: %v", err)
		return
	}

	ch := make(chan []byte, 8)

	s.mu.Lock()
	s.clients[ch] = struct{}{}
	s.mu.Unlock()

	// Writer goroutine: sends buffered state updates to the WebSocket client.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for msg := range ch {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}()

	// Read loop: blocks until client disconnects (sends Close frame or drops).
	conn.SetReadDeadline(time.Time{})
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	// Cleanup: remove from broadcast list, close the channel (unblocks writer), wait.
	s.mu.Lock()
	delete(s.clients, ch)
	s.mu.Unlock()
	close(ch)
	<-writerDone
	_ = conn.Close()
}

// broadcastLoop encodes the current state every interval and sends it to all
// connected WebSocket clients.
func (s *Server) broadcastLoop(interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for range tick.C {
		s.broadcastOnce()
	}
}

// broadcastOnce encodes the current state and fans it out to the connected
// WebSocket clients. A marshal failure degrades through the same sanitizing
// pass as writeJSON — never a silent skip, which left the WS feed permanently
// mute while the register bank stayed poisoned (audit E1).
func (s *Server) broadcastOnce() {
	v := s.stateFn()
	b, err := json.Marshal(v)
	if err != nil {
		logSanitizeOnce("ws broadcast", v, err)
		if b, err = json.Marshal(SanitizeNonFinite(v)); err != nil {
			return
		}
	}
	s.mu.Lock()
	for ch := range s.clients {
		select {
		case ch <- b:
		default: // skip slow consumer; it will catch up on the next tick
		}
	}
	s.mu.Unlock()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// Degrade, never 500: /state is QA's ground-truth window into a
		// corrupted simulator (audit E1 — a poisoned register bank decodes to
		// NaN), so non-finite floats become null fields instead of an error
		// page. Logged once per payload type; the 500 remains only for the
		// can't-happen case of the sanitized copy failing too.
		logSanitizeOnce("writeJSON", v, err)
		if b, err = json.Marshal(SanitizeNonFinite(v)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// cors wraps a handler to add permissive CORS headers. This allows a
// desktop-based GUI to reach the Pi's API without needing a proxy.
func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
