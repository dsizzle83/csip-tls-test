package report

// httpscan.go turns a reassembled — or decrypted — byte stream into §4.1.2
// Message Objects, with the same provenance discipline as mbapscan.go: every
// message carries the byte range it was decoded from and the frames those bytes
// arrived in.
//
// The HTTP head is parsed by hand rather than with net/http's readers, for one
// reason that matters to an evidence tool: http.ReadRequest canonicalises
// header names (accept -> Accept, X-FOO -> X-Foo). §4.1.2 requires the headers
// "present on the wire", and a log that silently re-cased them is a log that
// does not say what was on the wire. Parsing the head directly keeps the
// submitted evidence byte-faithful to the capture. Body framing then follows
// RFC 9112: Transfer-Encoding: chunked if present, else Content-Length, else
// (for a response on a connection that closes) the rest of the stream.

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/netdis"
)

// ScannedMessage is one Message Object plus the evidence it was derived from.
type ScannedMessage struct {
	Message CSIPMessage
	// Dir is the reassembled direction the message came from; nil when the
	// message was recovered from a decrypted stream, which has no single
	// reassembled direction of its own.
	Dir        *netdis.Direction
	Start, End int
	Frames     []int
}

// HTTPScan is one conversation's derived HTTP log.
type HTTPScan struct {
	Stream   *netdis.Stream
	Server   netip.AddrPort
	Messages []ScannedMessage
	// Problems record every place the stream could not be framed. A CSIP log
	// missing a message does not satisfy §4's "every HTTP(S) message
	// transferred as part of the test", so the gaps are named.
	Problems []string
}

// Messages returns just the JSON objects, for emission.
func (s *HTTPScan) LogMessages() []CSIPMessage {
	out := make([]CSIPMessage, len(s.Messages))
	for i, m := range s.Messages {
		out[i] = m.Message
	}
	return out
}

// TestLog wraps the derived messages as a §4.1.1 Test Log Object.
func (s *HTTPScan) TestLog(cid string, tests ...string) CSIPTestLog {
	return CSIPTestLog{Tests: tests, CID: cid, Messages: s.LogMessages()}
}

// First returns the first derived message of a type.
func (s *HTTPScan) First(typ string) (ScannedMessage, bool) {
	for _, m := range s.Messages {
		if m.Message.Type == typ {
			return m, true
		}
	}
	return ScannedMessage{}, false
}

// ByteStream is a plaintext direction to scan, plus the mapping from a byte
// offset back to the capture. It is the seam that lets the same scanner serve a
// cleartext conversation and a TLS conversation recovered through the run's key
// log: the caller supplies the offset-to-frame mapping it has.
type ByteStream struct {
	// Label names the direction in diagnostics, e.g. "69.0.0.20:51422 > 69.0.0.2:8080".
	Label string
	Data  []byte
	// At maps a byte offset to the frame that delivered it and that frame's
	// capture time. A stream whose At reports !ok for an offset cannot produce
	// a `time`, and the message is reported rather than emitted with a
	// fabricated one.
	At func(off int) (frame int, t time.Time, ok bool)
	// Frames maps a byte range to the frames covering it.
	Frames func(start, end int) []int
	// Dir, when non-nil, is the reassembled direction behind this stream, which
	// is what a check needs in order to cite the bytes.
	Dir *netdis.Direction
}

// DirectionStream adapts a reassembled cleartext direction.
func DirectionStream(d *netdis.Direction, frames []*netdis.Frame) ByteStream {
	byIndex := frameIndex(frames)
	return ByteStream{
		Label: d.Flow.String(),
		Data:  d.Bytes.Bytes(),
		Dir:   d,
		At: func(off int) (int, time.Time, bool) {
			n := d.Bytes.OffsetToPacket(off)
			f, ok := byIndex[n]
			if !ok {
				return 0, time.Time{}, false
			}
			return n, f.Time, true
		},
		Frames: func(start, end int) []int { return d.Bytes.PacketsFor(start, end) },
	}
}

// ScanHTTP derives Message Objects from a cleartext HTTP conversation.
func ScanHTTP(st *netdis.Stream, frames []*netdis.Frame, server netip.AddrPort) (*HTTPScan, error) {
	if st == nil {
		return nil, fmt.Errorf("report: ScanHTTP with no stream")
	}
	client, srv := st.Dirs[0], st.Dirs[1]
	if endpointAddrPort(client.Flow.Dst) != server {
		client, srv = srv, client
	}
	if endpointAddrPort(client.Flow.Dst) != server {
		return nil, fmt.Errorf("report: neither direction of %s is addressed to the HTTP server %s",
			st.Key, server)
	}
	sc := &HTTPScan{Stream: st, Server: server}
	sc.scan(DirectionStream(client, frames), MsgReq)
	sc.scan(DirectionStream(srv, frames), MsgResp)
	sort.SliceStable(sc.Messages, func(i, j int) bool {
		a, b := sc.Messages[i], sc.Messages[j]
		if a.Message.Time != b.Message.Time {
			return a.Message.Time < b.Message.Time
		}
		return firstFrame(a.Frames) < firstFrame(b.Frames)
	})
	return sc, nil
}

// ScanHTTPStreams derives Message Objects from two plaintext directions that
// are not netdis directions — the decrypted halves of a TLS session, typically.
func ScanHTTPStreams(clientToServer, serverToClient ByteStream) *HTTPScan {
	sc := &HTTPScan{}
	sc.scan(clientToServer, MsgReq)
	sc.scan(serverToClient, MsgResp)
	sort.SliceStable(sc.Messages, func(i, j int) bool {
		return sc.Messages[i].Message.Time < sc.Messages[j].Message.Time
	})
	return sc
}

// scan walks one plaintext direction, emitting one message per HTTP message.
func (s *HTTPScan) scan(bs ByteStream, typ string) {
	if bs.Dir != nil {
		if bs.Dir.MidStream {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s was captured mid-connection: its first captured byte is not known to be the "+
					"start of an HTTP message, so no `%s` entries were derived from it", bs.Label, typ))
			return
		}
		if !bs.Dir.Complete() {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s is missing %d byte(s); the messages after the gap cannot be framed",
				bs.Label, bs.Dir.PendingGap()))
			return
		}
	}
	data := bs.Data
	for off := 0; off < len(data); {
		// Tolerate the CRLFs some peers put between pipelined messages.
		for off < len(data) && (data[off] == '\r' || data[off] == '\n') {
			off++
		}
		if off >= len(data) {
			return
		}
		headEnd := bytes.Index(data[off:], []byte("\r\n\r\n"))
		if headEnd < 0 {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s: %d trailing byte(s) contain no complete HTTP head; an incomplete message "+
					"is reported rather than emitted", bs.Label, len(data)-off))
			return
		}
		headEnd += off
		head := string(data[off:headEnd])
		bodyStart := headEnd + 4

		msg, hdr, err := parseHead(head, typ)
		if err != nil {
			s.Problems = append(s.Problems, fmt.Sprintf("direction %s offset %d: %v", bs.Label, off, err))
			return
		}
		bodyLen, decoded, err := bodyLength(data[bodyStart:], hdr, typ, msg.Code)
		if err != nil {
			s.Problems = append(s.Problems, fmt.Sprintf("direction %s offset %d: %v", bs.Label, off, err))
			return
		}
		end := bodyStart + bodyLen
		if end > len(data) {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s offset %d: the message body claims %d bytes but only %d were captured; "+
					"the log omits it rather than emitting a truncated body", bs.Label, off, bodyLen, len(data)-bodyStart))
			return
		}
		msg.Body = string(decoded)

		frame, at, ok := bs.At(off)
		if !ok {
			s.Problems = append(s.Problems, fmt.Sprintf(
				"direction %s offset %d: no capture frame carries this byte, so the message would have no "+
					"`time`; it was not emitted", bs.Label, off))
			return
		}
		msg.Time = UnixTime(at)
		frames := []int{frame}
		if bs.Frames != nil {
			frames = bs.Frames(off, end)
		}
		s.Messages = append(s.Messages, ScannedMessage{
			Message: msg, Dir: bs.Dir, Start: off, End: end, Frames: frames,
		})
		off = end
	}
}

// header is one wire header, name preserved exactly as sent.
type header struct{ Name, Value string }

// parseHead decodes a start line and header block.
func parseHead(head, typ string) (CSIPMessage, []header, error) {
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return CSIPMessage{}, nil, fmt.Errorf("empty HTTP start line")
	}
	msg := CSIPMessage{Type: typ, Headers: map[string]string{}, Body: ""}
	start := lines[0]
	switch typ {
	case MsgReq:
		parts := strings.SplitN(start, " ", 3)
		if len(parts) != 3 {
			return CSIPMessage{}, nil, fmt.Errorf("request line %q is not `METHOD URI VERSION`", start)
		}
		msg.Method, msg.URI, msg.Vers = parts[0], parts[1], parts[2]
	default:
		parts := strings.SplitN(start, " ", 3)
		if len(parts) < 2 {
			return CSIPMessage{}, nil, fmt.Errorf("status line %q is not `VERSION CODE REASON`", start)
		}
		msg.Vers, msg.Code = parts[0], parts[1]
		reason := ""
		if len(parts) == 3 {
			reason = parts[2]
		}
		// The §4.1.2 example keeps the trailing CRLF on `reason` ("OK\r\n").
		// Reproducing it is not decoration: an ingest written against the
		// example may split on it.
		msg.Reason = reason + "\r\n"
	}
	var hdrs []header
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return CSIPMessage{}, nil, fmt.Errorf("header line %q has no colon", line)
		}
		value = strings.TrimLeft(value, " \t")
		hdrs = append(hdrs, header{Name: name, Value: value})
		// A repeated header name is joined with ", ", which is the field-value
		// combination RFC 9110 defines; the raw lines survive in the pcap the
		// log cites, so nothing is lost.
		if prev, dup := msg.Headers[name]; dup {
			msg.Headers[name] = prev + ", " + value
		} else {
			msg.Headers[name] = value
		}
	}
	return msg, hdrs, nil
}

func lookupHeader(hdrs []header, name string) (string, bool) {
	for _, h := range hdrs {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// bodyLength returns how many wire bytes the body occupies and its decoded
// content. For a chunked body the two differ: the log records the entity, and
// the byte range records where the chunk framing lived.
func bodyLength(rest []byte, hdrs []header, typ, code string) (int, []byte, error) {
	if te, ok := lookupHeader(hdrs, "Transfer-Encoding"); ok && strings.Contains(strings.ToLower(te), "chunked") {
		return decodeChunked(rest)
	}
	if cl, ok := lookupHeader(hdrs, "Content-Length"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			return 0, nil, fmt.Errorf("Content-Length %q is not a length", cl)
		}
		if n > len(rest) {
			return n, nil, nil // caller reports the truncation
		}
		return n, rest[:n], nil
	}
	if typ == MsgResp && !statusHasNoBody(code) {
		// No framing header on a response means the body is delimited by the
		// close of the connection (RFC 9112 §6.3): everything left is body.
		return len(rest), rest, nil
	}
	return 0, nil, nil
}

// statusHasNoBody covers the statuses RFC 9112 says never carry a body, so a
// 204 followed by the next response is not mistaken for a body swallowing it.
func statusHasNoBody(code string) bool {
	switch code {
	case "204", "304":
		return true
	}
	return strings.HasPrefix(code, "1")
}

// decodeChunked walks chunked framing, returning the encoded length and the
// decoded entity.
func decodeChunked(rest []byte) (int, []byte, error) {
	var body []byte
	off := 0
	for {
		eol := bytes.Index(rest[off:], []byte("\r\n"))
		if eol < 0 {
			return 0, nil, fmt.Errorf("chunked body ends without a chunk-size line")
		}
		sizeLine := string(rest[off : off+eol])
		if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
			sizeLine = sizeLine[:i] // chunk extensions
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 32)
		if err != nil || size < 0 {
			return 0, nil, fmt.Errorf("chunk size %q is not hexadecimal", sizeLine)
		}
		off += eol + 2
		if size == 0 {
			// Trailer section, then the final CRLF.
			for {
				e := bytes.Index(rest[off:], []byte("\r\n"))
				if e < 0 {
					return 0, nil, fmt.Errorf("chunked body ends without its terminating CRLF")
				}
				line := rest[off : off+e]
				off += e + 2
				if len(line) == 0 {
					return off, body, nil
				}
			}
		}
		if off+int(size)+2 > len(rest) {
			return 0, nil, fmt.Errorf("chunk of %d bytes runs past the captured stream", size)
		}
		body = append(body, rest[off:off+int(size)]...)
		off += int(size) + 2
	}
}
