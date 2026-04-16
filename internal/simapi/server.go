// Package simapi provides a lightweight HTTP + WebSocket API server that
// each simulator binary embeds. It exposes simulator state for GUI consumption
// and accepts injection/control commands from a Python GUI or any HTTP client.
//
// Endpoints:
//
//	GET  /state    — JSON snapshot of current simulator state (decoded values)
//	POST /inject   — inject field overrides; body: {"W_W": 4500.0, ...}
//	POST /control  — animation control; body: {"cmd":"pause"|"resume"|"reset", "speed":N}
//	GET  /registers — raw Modbus register dump (Modbus sims only; 404 if unsupported)
//	GET  /ws       — WebSocket: pushes /state JSON every 2 seconds
//
// All endpoints add Access-Control-Allow-Origin: * so a browser-based GUI
// running on a desktop can talk to a Pi simulator without a proxy.
package simapi

import (
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
}

// ControlFunc applies a control command to the simulator.
// May be nil to disable POST /control.
type ControlFunc func(cmd ControlCmd) error

// Server is the HTTP + WebSocket API server embedded by each simulator binary.
type Server struct {
	stateFn    StateFunc
	injectFn   InjectFunc
	registersFn RegistersFunc
	controlFn  ControlFunc

	mu      sync.Mutex
	clients map[chan []byte]struct{}
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
		clients:     make(map[chan []byte]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/state",     s.handleState)
	mux.HandleFunc("/inject",    s.handleInject)
	mux.HandleFunc("/control",   s.handleControl)
	mux.HandleFunc("/registers", s.handleRegisters)
	mux.HandleFunc("/ws",        s.handleWS)

	go func() {
		log.Printf("[simapi] API server on %s  (GET /state  POST /inject  POST /control  GET /ws)", addr)
		if err := http.ListenAndServe(addr, cors(mux)); err != nil {
			log.Printf("[simapi] server error on %s: %v", addr, err)
		}
	}()
	go s.broadcastLoop(2 * time.Second)
	return s
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
	w.WriteHeader(http.StatusNoContent)
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
	w.WriteHeader(http.StatusNoContent)
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
		b, err := json.Marshal(s.stateFn())
		if err != nil {
			continue
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
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
