//go:build integration

package tlsclient

import (
	"strings"
	"testing"

	"csip-tls-test/internal/csip/discovery"
)

// Compile-time assertion: WolfSSLFetcher must satisfy discovery.Fetcher.
var _ discovery.Fetcher = (*WolfSSLFetcher)(nil)

// TestWolfSSLFetcher_Get_ReturnsBodyOnly verifies that Get returns the
// XML body, not the raw HTTP response. This is the key semantic
// difference from Client.Get — the walker calls xml.Unmarshal directly
// on the result, so headers must be stripped.
func TestWolfSSLFetcher_Get_ReturnsBodyOnly(t *testing.T) {
	addr := startInProcessServer(t)

	fetcher, err := NewWolfSSLFetcher(goodClientConfig(addr))
	if err != nil {
		t.Fatalf("NewWolfSSLFetcher: %v", err)
	}
	defer fetcher.Free()

	body, err := fetcher.Get("/dcap")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if strings.HasPrefix(string(body), "HTTP/") {
		t.Error("Get returned raw HTTP response, expected body only")
	}
	if !strings.Contains(string(body), "<DeviceCapability") {
		t.Errorf("body missing <DeviceCapability>:\n%s", body)
	}
}

// TestWolfSSLFetcher_Get_SequentialCalls verifies that the fetcher can
// make multiple sequential Gets — each one redialing — from the same
// WolfSSLFetcher instance. This is the core behavior the discovery
// walker depends on: 8+ GETs through one fetcher.
func TestWolfSSLFetcher_Get_SequentialCalls(t *testing.T) {
	addr := startInProcessServer(t)

	fetcher, err := NewWolfSSLFetcher(goodClientConfig(addr))
	if err != nil {
		t.Fatalf("NewWolfSSLFetcher: %v", err)
	}
	defer fetcher.Free()

	for i := 0; i < 3; i++ {
		body, err := fetcher.Get("/dcap")
		if err != nil {
			t.Fatalf("Get call %d: %v", i+1, err)
		}
		if !strings.Contains(string(body), "<DeviceCapability") {
			t.Errorf("call %d: body missing <DeviceCapability>", i+1)
		}
	}
}

// TestWolfSSLFetcher_Get_ErrorOn404 verifies that a non-200 response
// from the server is surfaced as an error. The walker must not silently
// process error responses as if they were valid XML.
func TestWolfSSLFetcher_Get_ErrorOn404(t *testing.T) {
	addr := startInProcessServer(t)

	fetcher, err := NewWolfSSLFetcher(goodClientConfig(addr))
	if err != nil {
		t.Fatalf("NewWolfSSLFetcher: %v", err)
	}
	defer fetcher.Free()

	_, err = fetcher.Get("/does-not-exist")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "status 404") {
		t.Errorf("error should mention status 404, got: %v", err)
	}
}
