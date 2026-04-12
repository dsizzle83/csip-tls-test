package tlsserver

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// dcapXML is the canonical DeviceCapability response for Milestone 2.
const dcapXML = `<?xml version="1.0" encoding="UTF-8"?>
<DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap">
  <EndDeviceListLink href="/edev" all="0"/>
  <MirrorUsagePointListLink href="/mup" all="0"/>
  <SelfDeviceLink href="/sdev"/>
  <TimeLink href="/tm"/>
</DeviceCapability>`

// route is a deliberately minimal HTTP request router. Pure Go, no
// wolfSSL types — testable as a unit. Replaced by a real HTTP parser
// when Milestone 3 introduces POST bodies.
func route(request []byte) []byte {
	line, _, _ := bytes.Cut(request, []byte("\r\n"))
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) < 2 {
		return httpResponse(400, "text/plain", []byte("bad request"))
	}

	method := string(parts[0])
	path := string(parts[1])

	switch {
	case method == "GET" && path == "/dcap":
		return httpResponse(200, "application/sep+xml", []byte(dcapXML))
	default:
		return httpResponse(404, "text/plain", []byte("not found"))
	}
}

// dispatchHTTP bridges a raw wolfSSL request buffer to an http.Handler.
// It parses the HTTP request, injects the peer LFDI as X-Peer-LFDI,
// captures the handler's response via a buffered ResponseWriter, then
// serialises the result back to raw bytes for wolfssl.Write. Only one
// round-trip per connection is supported (Connection: close).
func dispatchHTTP(h http.Handler, raw []byte, peerLFDI string) []byte {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return httpResponse(400, "text/plain", []byte("bad request"))
	}
	if peerLFDI != "" {
		req.Header.Set("X-Peer-LFDI", peerLFDI)
	}
	w := &bufferedResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
	h.ServeHTTP(w, req)
	return buildHTTPResponse(w.statusCode, w.header, w.body.Bytes())
}

// bufferedResponseWriter captures an http.Handler's response so it can
// be written back over a raw wolfSSL connection.
type bufferedResponseWriter struct {
	header      http.Header
	body        bytes.Buffer
	statusCode  int
	wroteHeader bool
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.statusCode = code
		w.wroteHeader = true
	}
}

// buildHTTPResponse serializes an HTTP response from status, headers, and body.
// Forwards Content-Type and Location from the handler's response headers.
func buildHTTPResponse(status int, headers http.Header, body []byte) []byte {
	statusText := map[int]string{
		200: "OK",
		201: "Created",
		204: "No Content",
		400: "Bad Request",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		500: "Internal Server Error",
	}[status]
	if statusText == "" {
		statusText = "Unknown"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, statusText)
	if ct := headers.Get("Content-Type"); ct != "" {
		fmt.Fprintf(&sb, "Content-Type: %s\r\n", ct)
	}
	if loc := headers.Get("Location"); loc != "" {
		fmt.Fprintf(&sb, "Location: %s\r\n", loc)
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&sb, "Connection: close\r\n")
	fmt.Fprintf(&sb, "\r\n")

	result := []byte(sb.String())
	return append(result, body...)
}

// httpResponse is the convenience wrapper used by route() and error paths.
// For handler-based responses use buildHTTPResponse directly.
func httpResponse(status int, contentType string, body []byte) []byte {
	h := make(http.Header)
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return buildHTTPResponse(status, h, body)
}
