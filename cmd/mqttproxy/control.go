package main

import (
	"encoding/json"
	"net/http"
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

func (c *control) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/fault", c.handleFault)
	mux.HandleFunc("/inject", c.handleInject)
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

func (c *control) handleReset(w http.ResponseWriter, r *http.Request) {
	c.proxy.reset()
	c.writeState(w)
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
