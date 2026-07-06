package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// control is the HTTP API the mayhem engine drives. It runs on the hub LAN IP so
// the desktop dashboard can reach it (the broker itself stays localhost-bound).
type control struct {
	proxy  *Proxy
	broker string // upstream broker host:port, for message injection

	// mqttUser/mqttPass authenticate the direct /inject publish against the
	// real broker (TASK-013 / W7): once the broker's ACL requires
	// credentials, an anonymous CONNECT here is rejected and every mqtt-*
	// mayhem scenario that uses /inject (mqtt-malformed-control,
	// mqtt-stale-retained) goes BLIND. Empty mqttUser keeps sending the
	// original anonymous CONNECT, for a broker that still allows it.
	mqttUser string
	mqttPass string

	// holdMu/holdCancel guard the single in-flight /hold session (TASK-049:
	// duplicate-client-id squats the real hub's MQTT client ID to force a
	// mutual-kick reconnect storm). One hold at a time — a second /hold
	// while one is active is rejected rather than silently replacing it.
	holdMu     sync.Mutex
	holdCancel context.CancelFunc

	// stormMu/stormCancel is the same one-at-a-time guard for /storm
	// (TASK-051: sustained high-rate publish flood against a noise topic).
	stormMu     sync.Mutex
	stormCancel context.CancelFunc
}

type faultReq struct {
	Mode      string `json:"mode"`       // "pass" | "down" | "latency"
	LatencyMs int    `json:"latency_ms"` // for mode=latency
	DurationS int    `json:"duration_s"` // auto-reset after this long (0 = sticky)
}

type injectReq struct {
	Topic   string `json:"topic"`
	Payload string `json:"payload"` // raw bytes published as-is (may be malformed JSON)
	Retain  bool   `json:"retain"`
}

// holdReq is TASK-049's session-holding fault: open a CONNECT using ClientID
// and keep it alive for DurationS, forcing an MQTT broker to evict whatever
// session already holds that client ID (paho's mutual-kick reconnect storm)
// if ClientID collides with a real service — lexa-hub's, by default.
type holdReq struct {
	ClientID  string `json:"client_id"`
	DurationS int    `json:"duration_s"`
}

// maxHoldDurationS bounds /hold so an aborted mayhem run's storm ends on its
// own even if teardown's /reset never arrives (self-cancelling — the duration
// is the safety net, /reset is the fast path).
const maxHoldDurationS = 45

// stormReq is TASK-051's bus-backpressure fault: a rate-limited QoS-0 publish
// flood against Topic, sized to pressure mosquitto's max_queued_messages/
// max_inflight_messages bounds without touching the retained control topic.
type stormReq struct {
	Topic        string `json:"topic"`
	RateHz       int    `json:"rate_hz"`
	DurationS    int    `json:"duration_s"`
	PayloadBytes int    `json:"payload_bytes"`
}

// Caps on /storm parameters — self-limiting so an aborted run's flood ends on
// its own (same abort-safety contract as maxHoldDurationS).
const (
	maxStormRateHz    = 2000
	maxStormDurationS = 30
	maxStormPayload   = 4096
)

func (c *control) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/fault", c.handleFault)
	mux.HandleFunc("/inject", c.handleInject)
	mux.HandleFunc("/hold", c.handleHold)
	mux.HandleFunc("/storm", c.handleStorm)
	mux.HandleFunc("/reset", c.handleReset)
	mux.HandleFunc("/state", c.handleState)
	return mux
}

func (c *control) handleFault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req faultReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var mode faultMode
	switch req.Mode {
	case "down":
		mode = modeDown
	case "latency":
		mode = modeLatency
	case "pass", "":
		mode = modePass
	default:
		http.Error(w, "unknown mode (want pass|down|latency)", http.StatusBadRequest)
		return
	}
	c.proxy.setFault(mode, time.Duration(req.LatencyMs)*time.Millisecond, req.DurationS)
	c.writeState(w)
}

func (c *control) handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req injectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Topic == "" {
		http.Error(w, "bad json or missing topic", http.StatusBadRequest)
		return
	}
	// Inject straight onto the real broker, bypassing the proxy's fault layer —
	// this is a message-content fault, not a transport one.
	clientID := "mqttproxy-inject-" + time.Now().Format("150405.000")
	if err := mqttPublish(c.broker, clientID, c.mqttUser, c.mqttPass, req.Topic, []byte(req.Payload), req.Retain); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "topic": req.Topic, "retain": req.Retain})
}

// handleHold starts (or rejects, if one is already active) a session-holding
// squat of client_id. It returns immediately; the hold runs in a goroutine
// until duration_s elapses or /reset cancels it.
func (c *control) handleHold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req holdReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" {
		http.Error(w, "bad json or missing client_id", http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 || req.DurationS > maxHoldDurationS {
		http.Error(w, fmt.Sprintf("duration_s must be 1..%d", maxHoldDurationS), http.StatusBadRequest)
		return
	}

	c.holdMu.Lock()
	if c.holdCancel != nil {
		c.holdMu.Unlock()
		http.Error(w, "a hold is already active; POST /reset first", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.holdCancel = cancel
	c.holdMu.Unlock()

	go c.runHold(ctx, req.ClientID, req.DurationS)
	log.Printf("[mqttproxy] /hold: squatting client_id=%q for %ds", req.ClientID, req.DurationS)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "client_id": req.ClientID, "duration_s": req.DurationS})
}

// runHold opens one CONNECT as clientID and keeps it alive with periodic
// PINGREQs until ctx is cancelled (via /reset) or durationS elapses, then
// DISCONNECTs. It always clears holdCancel on exit so a later /hold is
// accepted.
func (c *control) runHold(ctx context.Context, clientID string, durationS int) {
	defer func() {
		c.holdMu.Lock()
		c.holdCancel = nil
		c.holdMu.Unlock()
	}()

	conn, err := dialAndConnect(c.broker, clientID, c.mqttUser, c.mqttPass, 5*time.Second)
	if err != nil {
		log.Printf("[mqttproxy] /hold: connect as %q failed: %v", clientID, err)
		return
	}
	defer conn.Close()

	timer := time.NewTimer(time.Duration(durationS) * time.Second)
	defer timer.Stop()
	// Keepalive well inside the 60 s negotiated in connectPacket.
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_, _ = conn.Write(disconnectPacket())
			log.Printf("[mqttproxy] /hold: released client_id=%q (reset)", clientID)
			return
		case <-timer.C:
			_, _ = conn.Write(disconnectPacket())
			log.Printf("[mqttproxy] /hold: released client_id=%q (duration elapsed)", clientID)
			return
		case <-ticker.C:
			if _, err := conn.Write(pingreqPacket()); err != nil {
				log.Printf("[mqttproxy] /hold: keepalive failed for client_id=%q: %v", clientID, err)
				return
			}
		}
	}
}

// handleStorm starts (or rejects, if one is already active) a rate-limited
// publish flood against topic. It returns immediately; the storm runs in a
// goroutine until duration_s elapses or /reset cancels it.
func (c *control) handleStorm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req stormReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Topic == "" {
		http.Error(w, "bad json or missing topic", http.StatusBadRequest)
		return
	}
	if req.RateHz <= 0 || req.RateHz > maxStormRateHz {
		http.Error(w, fmt.Sprintf("rate_hz must be 1..%d", maxStormRateHz), http.StatusBadRequest)
		return
	}
	if req.DurationS <= 0 || req.DurationS > maxStormDurationS {
		http.Error(w, fmt.Sprintf("duration_s must be 1..%d", maxStormDurationS), http.StatusBadRequest)
		return
	}
	if req.PayloadBytes < 0 || req.PayloadBytes > maxStormPayload {
		http.Error(w, fmt.Sprintf("payload_bytes must be 0..%d", maxStormPayload), http.StatusBadRequest)
		return
	}

	c.stormMu.Lock()
	if c.stormCancel != nil {
		c.stormMu.Unlock()
		http.Error(w, "a storm is already active; POST /reset first", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.stormCancel = cancel
	c.stormMu.Unlock()

	go c.runStorm(ctx, req.Topic, req.RateHz, req.DurationS, req.PayloadBytes)
	log.Printf("[mqttproxy] /storm: flooding topic=%q at %d Hz for %ds (%d B payload)",
		req.Topic, req.RateHz, req.DurationS, req.PayloadBytes)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "topic": req.Topic, "rate_hz": req.RateHz, "duration_s": req.DurationS, "payload_bytes": req.PayloadBytes,
	})
}

// runStorm opens one CONNECT and publishes QoS-0 messages of payloadBytes
// zeros to topic at rateHz until ctx is cancelled or durationS elapses.
// QoS 0 is deliberate: a QoS-1 flood would block on the proxy's own acks and
// self-throttle, defeating the point of pressuring the broker's queue.
func (c *control) runStorm(ctx context.Context, topic string, rateHz, durationS, payloadBytes int) {
	defer func() {
		c.stormMu.Lock()
		c.stormCancel = nil
		c.stormMu.Unlock()
	}()

	clientID := "mqttproxy-storm-" + time.Now().Format("150405.000")
	conn, err := dialAndConnect(c.broker, clientID, c.mqttUser, c.mqttPass, 5*time.Second)
	if err != nil {
		log.Printf("[mqttproxy] /storm: connect failed: %v", err)
		return
	}
	defer conn.Close()

	pkt := publishPacket(topic, make([]byte, payloadBytes), false)

	deadline := time.NewTimer(time.Duration(durationS) * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second / time.Duration(rateHz))
	defer ticker.Stop()

	sent := 0
	for {
		select {
		case <-ctx.Done():
			_, _ = conn.Write(disconnectPacket())
			log.Printf("[mqttproxy] /storm: stopped topic=%q after %d messages (reset)", topic, sent)
			return
		case <-deadline.C:
			_, _ = conn.Write(disconnectPacket())
			log.Printf("[mqttproxy] /storm: finished topic=%q after %d messages (duration elapsed)", topic, sent)
			return
		case <-ticker.C:
			if _, err := conn.Write(pkt); err != nil {
				log.Printf("[mqttproxy] /storm: write failed after %d messages: %v", sent, err)
				return
			}
			sent++
		}
	}
}

func (c *control) handleReset(w http.ResponseWriter, r *http.Request) {
	c.proxy.reset()
	c.cancelHold()
	c.cancelStorm()
	c.writeState(w)
}

// cancelHold cancels the active /hold session, if any. Safe to call when none
// is active.
func (c *control) cancelHold() {
	c.holdMu.Lock()
	cancel := c.holdCancel
	c.holdMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// cancelStorm cancels the active /storm flood, if any. Safe to call when none
// is active.
func (c *control) cancelStorm() {
	c.stormMu.Lock()
	cancel := c.stormCancel
	c.stormMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *control) handleState(w http.ResponseWriter, r *http.Request) {
	c.writeState(w)
}

func (c *control) writeState(w http.ResponseWriter) {
	mode, latMs, conns := c.proxy.state()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mode":       mode,
		"latency_ms": latMs,
		"live_conns": conns,
		"upstream":   c.broker,
	})
}
