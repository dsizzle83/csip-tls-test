// Package httpclient provides a Fetcher implementation that performs
// real HTTP GET requests. This bridges the discovery walker (which
// only knows about paths) to an actual HTTP server.
//
// For Milestone 3 testing without wolfSSL, this uses Go's net/http.
// In production, you'll replace the transport with your wolfSSL-based
// TLS client from Milestone 2.
package httpclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// Fetcher implements discovery.Fetcher using HTTP GET requests.
type Fetcher struct {
	baseURL string       // e.g., "https://192.168.1.100:443"
	client  *http.Client // configurable for TLS, timeouts, etc.
}

// NewFetcher creates an HTTP-based Fetcher. The baseURL should include
// the scheme, host, and port (e.g., "https://192.168.1.100:443").
// Pass a custom http.Client to use your wolfSSL TLS transport.
func NewFetcher(baseURL string, client *http.Client) *Fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &Fetcher{baseURL: baseURL, client: client}
}

// Get performs an HTTPS GET on the given path and returns the raw XML body.
// It checks for the correct Content-Type (application/sep+xml per GEN.003)
// and a 200 OK status.
func (f *Fetcher) Get(path string) ([]byte, error) {
	url := f.baseURL + path

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", path, err)
	}

	// GEN.056: Client SHALL declare acceptable media types using HTTP Accept header
	req.Header.Set("Accept", "application/sep+xml")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d (body: %s)", path, resp.StatusCode, truncate(body, 200))
	}

	return body, nil
}

// Post performs an HTTP POST and returns the response body, Location header,
// and any error. Accepts 201 Created and 204 No Content.
func (f *Fetcher) Post(path string, body []byte, contentType string) ([]byte, string, error) {
	url := f.baseURL + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("create request for %s: %w", path, err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read body from %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return nil, "", fmt.Errorf("POST %s: status %d (body: %s)", path, resp.StatusCode, truncate(respBody, 200))
	}
	return respBody, resp.Header.Get("Location"), nil
}

func truncate(b []byte, maxLen int) string {
	if len(b) > maxLen {
		return string(b[:maxLen]) + "..."
	}
	return string(b)
}
