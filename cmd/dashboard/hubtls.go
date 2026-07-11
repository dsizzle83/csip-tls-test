package main

// hubtls.go — TLS transport for the "hub" backend (lexa-api, :9100).
//
// Workstream B: lexa-api now serves HTTPS on :9100 with a per-device
// self-signed ECDSA P-256 leaf cert generated on the hub. There is no CA to
// validate against, so the bench posture is InsecureSkipVerify: true — this is
// the air-gapped 69.0.0.x LAN over a trusted link; the security boundary is the
// companion app's fingerprint pinning, not this lab dashboard. Every
// dashboard-side hub consumer (the /api/hub reverse-proxy mount, the merged log
// stream, and the Mayhem/replay driver HTTP helpers) uses this transport.
//
// Skip-verify TLS config is ignored for plain http:// requests, so the drivers
// and the logmux — which reach the http sims through the SAME client — are
// unaffected; only the https hub URL exercises it. Bearer-token auth
// (hubauth.go) is unchanged and orthogonal.

import (
	"crypto/tls"
	"net/http"
)

// benchHubTransport returns an http.Transport that skips TLS certificate
// verification, for the hub's self-signed :9100 leaf (see file comment).
func benchHubTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
