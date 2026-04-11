package tlsclient

import "fmt"

// WolfSSLFetcher implements the discovery.Fetcher interface using
// wolfSSL mTLS. The wolfSSL context — cert loading and cipher
// configuration — is created once in NewWolfSSLFetcher and reused
// across calls. Each Get opens a fresh TLS session, performs one HTTP
// request, then closes the session (the "redial per request" strategy).
// Persistent connections are deferred to a later milestone.
type WolfSSLFetcher struct {
	client *Client
}

// NewWolfSSLFetcher allocates a wolfSSL context configured for CSIP mTLS.
// Call Free when the fetcher is no longer needed.
func NewWolfSSLFetcher(cfg Config) (*WolfSSLFetcher, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return &WolfSSLFetcher{client: c}, nil
}

// Free releases the underlying wolfSSL context. After Free, the
// WolfSSLFetcher must not be used.
func (f *WolfSSLFetcher) Free() {
	f.client.Free()
}

// Get performs a single HTTP GET over a fresh wolfSSL mTLS session and
// returns the response body. The TLS session is opened and closed within
// this call. Status must be 200 and Content-Type must be
// application/sep+xml (GEN.003); any other response is returned as an error.
//
// Get satisfies discovery.Fetcher.
func (f *WolfSSLFetcher) Get(path string) ([]byte, error) {
	if err := f.client.Dial(); err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer f.client.Close()

	raw, err := f.client.Get(path)
	if err != nil {
		return nil, err
	}

	resp, err := parseHTTPResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse response from %s: %w", path, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
	}
	if resp.ContentType != "application/sep+xml" {
		return nil, fmt.Errorf("GET %s: Content-Type %q, want application/sep+xml (GEN.003)", path, resp.ContentType)
	}
	return resp.Body, nil
}
