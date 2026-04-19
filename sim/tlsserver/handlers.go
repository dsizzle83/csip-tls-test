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
// serialises the result back to raw bytes for wolfssl.Write.
// connClose mirrors the client's Connection header back in the response.
func dispatchHTTP(h http.Handler, raw []byte, peerLFDI string, connClose bool) []byte {
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
	return buildHTTPResponse(w.statusCode, w.header, w.body.Bytes(), connClose)
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

// hopByHopHeaders lists headers that must not be forwarded end-to-end.
// Connection management headers are owned by this layer.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"transfer-encoding":   true,
	"te":                  true,
	"trailer":             true,
	"upgrade":             true,
	"proxy-authorization": true,
	"proxy-authenticate":  true,
	// content-length is recalculated from the captured body; skip the handler value.
	"content-length": true,
}

// buildHTTPResponse serializes an HTTP response from status, headers, and body.
// Forwards all response headers set by the handler except hop-by-hop headers;
// always appends Content-Length. Sends Connection: keep-alive when connClose
// is false (the normal persistent-connection case) or Connection: close when
// the client requested close or the session is ending.
func buildHTTPResponse(status int, headers http.Header, body []byte, connClose bool) []byte {
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
	for k, vals := range headers {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	if connClose {
		fmt.Fprintf(&sb, "Connection: close\r\n")
	} else {
		fmt.Fprintf(&sb, "Connection: keep-alive\r\n")
	}
	fmt.Fprintf(&sb, "\r\n")

	result := []byte(sb.String())
	return append(result, body...)
}

// httpResponse is the convenience wrapper used by route() and error paths.
// Always sends Connection: close since route is a single-request static handler.
func httpResponse(status int, contentType string, body []byte) []byte {
	h := make(http.Header)
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return buildHTTPResponse(status, h, body, true)
}
