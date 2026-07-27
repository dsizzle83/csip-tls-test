package suitecsip

// httpdis.go turns one direction's DECRYPTED byte stream back into HTTP/1.1
// messages, keeping every message's offsets so the citation phase can point at
// the TLS records — and therefore the capture frames — that carried it.
//
// # Why hand-rolled rather than net/http
//
// http.ReadRequest and http.ReadResponse would parse these bytes correctly, but
// they read through a bufio.Reader that buffers ahead, so the caller cannot
// learn where in the stream a message ended. Offsets are the whole point here:
// an assertion that says "the DUT sent GET /dcap" and cannot say WHICH BYTES
// said so is prose, not evidence. Parsing the slice directly costs a hundred
// lines and buys exact [start,end) spans for every request, response and body.
//
// The parser is deliberately strict about framing (request line, CRLF header
// block, Content-Length or chunked) and deliberately lenient about everything
// else. Its job is to recover what was said, not to judge it: whether a missing
// Host header or a wrong content type is a conformance failure is a question
// for a check, and a parser that refused such a message would deny the check
// the evidence it needs to report the failure.

import (
	"bytes"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// MessageKind distinguishes the two directions' messages.
type MessageKind string

// The two kinds.
const (
	Request  MessageKind = "request"
	Response MessageKind = "response"
)

// Message is one recovered HTTP/1.1 message with its provenance.
type Message struct {
	Kind MessageKind

	// Request line.
	Method string
	Target string
	// Path is Target with any query string removed, which is what a procedure's
	// "GET /dcap" means; Query keeps the rest, which is what the list-paging
	// criteria are about.
	Path  string
	Query string

	// Status line.
	Proto  string
	Status int
	Reason string

	Header textproto.MIMEHeader
	Body   []byte
	// BodyTruncated is set when the stream ended before Content-Length bytes
	// arrived — a capture that stopped mid-response, not a malformed peer.
	BodyTruncated bool

	// Start and End bound the message in the decrypted stream.
	Start, End int
	// CipherStart and CipherEnd bound the TLS records that carried it in the
	// RE-ASSEMBLED CIPHERTEXT stream. This is the range an evidence citation
	// uses, because it is the range that exists in the pcap.
	CipherStart, CipherEnd int
	// Frames are the capture frames those records occupied.
	Frames []int
	// Records are the record indices within the direction.
	Records []int
	// Time is the capture timestamp of the first frame carrying the message,
	// which is the defensible clock for every timing criterion in this suite.
	Time time.Time
}

// Line renders the message's start line for an assertion's Observed field.
func (m *Message) Line() string {
	if m == nil {
		return "(none)"
	}
	if m.Kind == Request {
		return m.Method + " " + m.Target
	}
	return fmt.Sprintf("%d %s", m.Status, m.Reason)
}

// ContentType is the media type without parameters, lower-cased.
func (m *Message) ContentType() string {
	if m == nil {
		return ""
	}
	v := m.Header.Get("Content-Type")
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// SEP parses the body as sep+xml.
func (m *Message) SEP() (*Node, error) {
	if m == nil || len(m.Body) == 0 {
		return nil, fmt.Errorf("suitecsip: %s has no body to parse", m.Line())
	}
	return ParseSEP(m.Body)
}

// Exchange pairs a request with the response that answered it. Response is nil
// when the capture ended before the answer arrived, which is itself evidence
// (an unanswered request is what a hung server looks like).
type Exchange struct {
	Req  *Message
	Resp *Message
}

// Frames are every capture frame the exchange occupied, request and response.
func (e Exchange) Frames() []int {
	var out []int
	if e.Req != nil {
		out = append(out, e.Req.Frames...)
	}
	if e.Resp != nil {
		out = append(out, e.Resp.Frames...)
	}
	return dedupeInts(out)
}

// String renders "GET /dcap -> 200" for a report line.
func (e Exchange) String() string {
	if e.Resp == nil {
		return e.Req.Line() + " -> (no response in the capture)"
	}
	return e.Req.Line() + " -> " + e.Resp.Line()
}

// Latency is the wall time between the request's first frame and the response's
// first frame, measured from CAPTURE timestamps. The second result is false
// when either timestamp is missing, in which case a timing criterion must SKIP
// rather than substitute the harness clock.
func (e Exchange) Latency() (time.Duration, bool) {
	if e.Req == nil || e.Resp == nil || e.Req.Time.IsZero() || e.Resp.Time.IsZero() {
		return 0, false
	}
	return e.Resp.Time.Sub(e.Req.Time), true
}

// parseMessages walks a decrypted direction and recovers every message in it.
//
// methods, when non-nil, supplies the request methods in order so that a
// response to HEAD is known to have no body — the one place where a response
// cannot be framed without knowing its request. A parse that runs out of bytes
// mid-message stops and reports how far it got: a truncated capture yields the
// messages that DID complete, which is the honest outcome.
func parseMessages(kind MessageKind, plain *plainStream, methods []string) ([]*Message, error) {
	var out []*Message
	off := 0
	data := plain.data
	for off < len(data) {
		// Skip any stray CRLFs between messages (legal, and some stacks emit
		// them after a chunked body).
		for off < len(data) && (data[off] == '\r' || data[off] == '\n') {
			off++
		}
		if off >= len(data) {
			break
		}
		method := ""
		if kind == Response && len(methods) > len(out) {
			method = methods[len(out)]
		}
		m, next, err := parseOne(kind, data, off, method)
		if m == nil {
			if err != nil {
				return out, fmt.Errorf("suitecsip: %s stream at byte %d: %w", kind, off, err)
			}
			break
		}
		m.Start, m.End = off, next
		plain.locate(m)
		out = append(out, m)
		off = next
	}
	return out, nil
}

// parseOne parses a single message starting at off. It returns the message and
// the offset just past it, or (nil, off, err) when the remaining bytes are not
// a complete message.
func parseOne(kind MessageKind, data []byte, off int, reqMethod string) (*Message, int, error) {
	hdrEnd := bytes.Index(data[off:], []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		// No complete header block: the capture ended mid-message.
		return nil, off, nil
	}
	block := string(data[off : off+hdrEnd])
	bodyStart := off + hdrEnd + 4

	lines := strings.Split(block, "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, off, fmt.Errorf("empty start line")
	}
	m := &Message{Kind: kind, Header: textproto.MIMEHeader{}}
	if err := parseStartLine(m, lines[0]); err != nil {
		return nil, off, err
	}
	if err := parseHeaderLines(m, lines[1:]); err != nil {
		return nil, off, err
	}

	n, truncated, err := bodyLength(m, data, bodyStart, reqMethod)
	if err != nil {
		return nil, off, err
	}
	m.BodyTruncated = truncated
	end := bodyStart + n
	if end > len(data) {
		end = len(data)
	}
	if isChunked(m) {
		body, consumed, trunc := dechunk(data[bodyStart:])
		m.Body = body
		m.BodyTruncated = trunc
		end = bodyStart + consumed
	} else {
		m.Body = append([]byte(nil), data[bodyStart:end]...)
	}
	return m, end, nil
}

func parseStartLine(m *Message, line string) error {
	parts := strings.SplitN(line, " ", 3)
	if m.Kind == Request {
		if len(parts) < 2 {
			return fmt.Errorf("request line %q has no target", line)
		}
		m.Method, m.Target = parts[0], parts[1]
		if len(parts) > 2 {
			m.Proto = parts[2]
		}
		if i := strings.IndexByte(m.Target, '?'); i >= 0 {
			m.Path, m.Query = m.Target[:i], m.Target[i+1:]
		} else {
			m.Path = m.Target
		}
		return nil
	}
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return fmt.Errorf("status line %q is not an HTTP response", line)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("status line %q has a non-numeric code", line)
	}
	m.Proto, m.Status = parts[0], code
	if len(parts) > 2 {
		m.Reason = parts[2]
	}
	return nil
}

func parseHeaderLines(m *Message, lines []string) error {
	var lastKey string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if ln[0] == ' ' || ln[0] == '\t' {
			// Obsolete line folding. Deprecated by RFC 7230 and never emitted
			// by a 2030.5 stack, but recovering it costs two lines and losing
			// it would silently truncate a header value.
			if lastKey != "" {
				vals := m.Header[lastKey]
				if len(vals) > 0 {
					vals[len(vals)-1] += " " + strings.TrimSpace(ln)
				}
			}
			continue
		}
		i := strings.IndexByte(ln, ':')
		if i < 0 {
			return fmt.Errorf("header line %q has no colon", ln)
		}
		key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(ln[:i]))
		val := strings.TrimSpace(ln[i+1:])
		m.Header[key] = append(m.Header[key], val)
		lastKey = key
	}
	return nil
}

func isChunked(m *Message) bool {
	for _, v := range m.Header["Transfer-Encoding"] {
		if strings.Contains(strings.ToLower(v), "chunked") {
			return true
		}
	}
	return false
}

// bodyLength decides how many bytes follow the header block, per RFC 7230 §3.3.3
// as narrowed by 2030.5's usage.
func bodyLength(m *Message, data []byte, bodyStart int, reqMethod string) (int, bool, error) {
	avail := len(data) - bodyStart
	if isChunked(m) {
		return 0, false, nil // handled by dechunk
	}
	if m.Kind == Response {
		switch {
		case m.Status >= 100 && m.Status < 200, m.Status == 204, m.Status == 304:
			return 0, false, nil
		case strings.EqualFold(reqMethod, "HEAD"):
			return 0, false, nil
		}
	}
	if v := m.Header.Get("Content-Length"); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return 0, false, fmt.Errorf("Content-Length %q is not a length", v)
		}
		if n > avail {
			return avail, true, nil
		}
		return n, false, nil
	}
	if m.Kind == Request {
		// No Content-Length and not chunked: RFC 7230 says no body.
		return 0, false, nil
	}
	// A response with neither is delimited by connection close, so everything
	// remaining is its body. On a keep-alive 2030.5 session this only happens
	// for the final response before the peer closed.
	return avail, false, nil
}

// dechunk decodes a chunked body, returning the decoded bytes, how many raw
// bytes it consumed, and whether it ran out mid-body.
func dechunk(raw []byte) (body []byte, consumed int, truncated bool) {
	off := 0
	for {
		nl := bytes.Index(raw[off:], []byte("\r\n"))
		if nl < 0 {
			return body, len(raw), true
		}
		sizeLine := string(raw[off : off+nl])
		if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
			sizeLine = sizeLine[:i] // chunk extensions
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || size < 0 {
			return body, off, true
		}
		off += nl + 2
		if size == 0 {
			// Trailer section, terminated by a blank line.
			if end := bytes.Index(raw[off:], []byte("\r\n")); end >= 0 {
				off += end + 2
			} else {
				return body, len(raw), true
			}
			return body, off, false
		}
		if off+int(size) > len(raw) {
			return append(body, raw[off:]...), len(raw), true
		}
		body = append(body, raw[off:off+int(size)]...)
		off += int(size)
		// Chunk data is followed by CRLF.
		if off+2 <= len(raw) {
			off += 2
		} else {
			return body, len(raw), true
		}
	}
}

func dedupeInts(v []int) []int {
	if len(v) == 0 {
		return nil
	}
	seen := make(map[int]bool, len(v))
	out := make([]int, 0, len(v))
	for _, n := range v {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sortInts(out)
	return out
}

func sortInts(v []int) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
