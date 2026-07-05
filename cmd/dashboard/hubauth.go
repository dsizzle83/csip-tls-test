package main

// hubauth.go — bearer-token presentation for lexa-api (:9100), the hub's
// HTTP status/log surface. TASK-014 (W7, AD-008): lexa-api now requires
// `Authorization: Bearer <token>` on /status and /logs once it's configured
// with a non-empty api_token_file; every dashboard-side consumer of the
// "hub" backend must present the same token — the reverse proxy mount, the
// merged log stream (logmux.go), and the Mayhem/replay driver HTTP helpers.
//
// Scoped deliberately to the "hub" backend name only: gridsim/solar/battery/
// meter/ev/mqttproxy stay open bench surfaces (AD-008) and must never
// receive the token — leaking it to every sim buys nothing and widens the
// token's exposure for no reason.
//
// Staged rollout: an empty token (the default — no -hub-token-file flag, or
// an empty/missing file) means "don't set the header", which is exactly
// today's behavior against a lexa-api that isn't requiring auth yet.

import (
	"net/http"
	"os"
	"strings"
)

// hubToken is the bearer token presented to the "hub" backend. Loaded once
// at startup by loadHubToken; empty means auth is off, matching lexa-api's
// own staged-rollout default.
var hubToken string

// loadHubToken reads the bearer token from path. An empty path is a no-op
// (auth stays disabled). A configured path that's missing or empty is
// logged by the caller but otherwise non-fatal — the dashboard must not
// refuse to start because a token hasn't been distributed yet during
// staged rollout; it just runs open against the hub, same as before.
func loadHubToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// setHubAuth adds the Authorization header to req iff name is the "hub"
// backend and a token is configured. Every dashboard-side hub consumer
// (proxy Director, logmux follower, Mayhem/replay driver helpers) must
// route its outgoing hub requests through this func rather than setting
// the header itself, so there is exactly one place that decides "hub gets
// the token, nobody else does."
func setHubAuth(req *http.Request, name string) {
	if name == "hub" && hubToken != "" {
		req.Header.Set("Authorization", "Bearer "+hubToken)
	}
}
