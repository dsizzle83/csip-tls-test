package tlsserver

import (
	"bytes"
	"fmt"
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

func httpResponse(status int, contentType string, body []byte) []byte {
	statusText := map[int]string{
		200: "OK",
		400: "Bad Request",
		404: "Not Found",
	}[status]
	if statusText == "" {
		statusText = "Unknown"
	}
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		status, statusText, contentType, len(body), body))
}
