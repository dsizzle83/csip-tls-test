package report

// csiplog.go implements Chapter 4 of SS-CSIP-RESULTS-v1.1: the Detailed Test
// Logs for an IEEE 2030.5 / CSIP submission.
//
// The requirement that shapes everything is §4's first sentence: the logs
// contain every HTTP(S) message transferred as part of the test, in UNENCRYPTED
// form. A CSIP session is mutually-authenticated TLS end to end, so a log that
// satisfies this can only come from a party that holds the session keys. That
// is the reason the bench exports an NSS key log and the reason ScanHTTP takes
// a decrypted stream: the alternative — logging what our own client library
// thought it sent — is a log that cannot be checked against the capture, and an
// evidence artefact nobody can check is not evidence.
//
// Note the deliberate tension with Chapter 5, which wants the TLS layer RAW for
// COMM-004. The two artefacts are complementary, not alternatives: Chapter 4
// proves what was said, Chapter 5 proves what happened when nothing could be
// said because the handshake was refused. A tool must emit both from one run,
// which is why the submission carries the pcap alongside the JSON.
//
// Two shapes the §4.1.2 CONTENTS TABLE omits and the §4.1.2 EXAMPLE requires: a
// response message carries `code` and `reason`, and `code` is a STRING ("200"),
// not a number, with `reason` retaining its trailing CRLF ("OK\r\n"). The
// emitter follows the example, because a generator matching only the table
// would produce logs an ingest written against the worked example rejects.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Message types, §4.1.2.
const (
	// MsgReq — an HTTP request.
	MsgReq = "req"
	// MsgResp — an HTTP response.
	MsgResp = "resp"
)

// CSIPMessage is one Message Object: a single HTTP request or response,
// recorded with enough fidelity for SunSpec to re-verify the outcome without
// the lab's tooling.
type CSIPMessage struct {
	// Time is a JSON number of seconds — not a formatted date string. Second
	// accuracy is a MUST and sub-second is "ideally"; the emitter always writes
	// sub-second decimals, because every CSIP timing criterion (poll interval,
	// response latency, event start) needs them.
	Time float64 `json:"time"`
	// Type is MsgReq or MsgResp, exactly.
	Type string `json:"type"`
	// Method and URI are the request line's. They are carried on responses too
	// when known, so a response can be read without its request in hand; the
	// example omits them there, so they are omitempty.
	Method string `json:"method,omitempty"`
	URI    string `json:"uri,omitempty"`
	// Vers is the HTTP version string, e.g. "HTTP/1.1".
	Vers string `json:"vers"`
	// Code and Reason appear on responses. Code is a STRING per the §4.1.2
	// example; Reason retains the trailing CRLF the example shows.
	Code   string `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Headers is EVERY header present on the wire, as string key/value pairs.
	// A log that dropped a header would make a header-conditioned criterion
	// unverifiable, so the scanner never filters.
	Headers map[string]string `json:"headers"`
	// Body is the message body, and is the empty string — not absent, not null —
	// when there is none. §4.1.2 is explicit about that.
	Body string `json:"body"`
}

// CSIPTestLog is one Test Log Object: the HTTP messages evidencing one or more
// named test procedures, with the optional context id.
type CSIPTestLog struct {
	Tests []string `json:"tests"`
	// CID is the context id. §4.1.1's prose calls it optional while the JSON
	// format block shows it unconditionally; it is emitted when the operator
	// supplies one and omitted otherwise. Unlike the Modbus document, v1.1 of
	// the CSIP document did NOT remove it.
	CID      string        `json:"cid,omitempty"`
	Messages []CSIPMessage `json:"messages"`
}

// CSIPTestLogs is the Test Logs Object: many test logs in one document, with
// the shared context id that stitches separately-archived documents back
// together. Always emitting a stable cid per campaign costs nothing and is the
// only mechanism the format has for that association.
type CSIPTestLogs struct {
	Logs []CSIPTestLog `json:"logs"`
	CID  string        `json:"cid,omitempty"`
}

// JSON renders the Test Logs Object.
func (l *CSIPTestLogs) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: encode CSIP test logs: %w", err)
	}
	return append(data, '\n'), nil
}

// ParseCSIPTestLogs reads a Test Logs Object back, rejecting unknown fields.
func ParseCSIPTestLogs(data []byte) (*CSIPTestLogs, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	out := &CSIPTestLogs{}
	if err := dec.Decode(out); err != nil {
		return nil, fmt.Errorf("report: parse CSIP test logs: %w", err)
	}
	return out, nil
}

// tlsRecordPrefix recognises the first bytes of a TLS record: content type
// 20..23 followed by a 0x03 major version. A `body` starting like that is
// ciphertext that was logged verbatim instead of being decrypted, which is
// exactly the failure §4 forbids, so it is detected rather than passed through.
func tlsRecordPrefix(s string) bool {
	if len(s) < 3 {
		return false
	}
	return s[0] >= 20 && s[0] <= 23 && s[1] == 0x03
}

// ValidateCSIPTestLogs applies every machine-checkable rule Chapter 4 states.
//
//	RPT-051  tests[] and messages[] present; cid optional
//	RPT-052  time/type/vers/headers/body on every message; body "" not absent
//	RPT-053  time is a number in seconds, sub-second decimals present
//	RPT-054  a response carries code (a string) and reason
//	RPT-050  bodies are plaintext HTTP, not TLS records
//	RPT-055  logs[] is the container element
func ValidateCSIPTestLogs(l *CSIPTestLogs) []string {
	var f []string
	if l == nil || len(l.Logs) == 0 {
		return []string{"Test Logs Object carries no `logs` array (§4.1.3)"}
	}
	for i, log := range l.Logs {
		where := fmt.Sprintf("logs[%d]", i)
		if len(log.Tests) == 0 {
			f = append(f, where+": `tests` is empty; a log that names no test procedure evidences nothing (§4.1.1)")
		}
		if len(log.Messages) == 0 {
			f = append(f, where+": `messages` is empty (§4.1.1)")
		}
		for j, m := range log.Messages {
			at := fmt.Sprintf("%s.messages[%d]", where, j)
			if m.Time == 0 {
				f = append(f, at+": `time` is absent or zero (§4.1.2: a value in seconds, second accuracy MUST)")
			}
			switch m.Type {
			case MsgReq:
				if m.Method == "" {
					f = append(f, at+": a request has no `method`")
				}
				if m.URI == "" {
					f = append(f, at+": a request has no `uri`")
				}
			case MsgResp:
				// The contents table omits these; the worked example requires
				// them, and an ingest built from the example needs them.
				if m.Code == "" {
					f = append(f, at+": a response has no `code` (the §4.1.2 example emits `\"code\": \"200\"`)")
				} else if _, err := parseStatusCode(m.Code); err != nil {
					f = append(f, fmt.Sprintf("%s: `code` %q is not a three-digit HTTP status as a string", at, m.Code))
				}
				if m.Reason == "" {
					f = append(f, at+": a response has no `reason`")
				}
			case "":
				f = append(f, at+": `type` is absent (§4.1.2: \"req\" or \"resp\")")
			default:
				f = append(f, fmt.Sprintf("%s: `type` is %q, not \"req\" or \"resp\"", at, m.Type))
			}
			if m.Vers == "" {
				f = append(f, at+": `vers` is absent")
			}
			if m.Headers == nil {
				f = append(f, at+": `headers` is absent; §4.1.2 requires the header key/value pairs, "+
					"and an empty object is how a message with no headers is expressed")
			}
			if tlsRecordPrefix(m.Body) {
				f = append(f, at+": `body` begins with a TLS record header — the message was logged as "+
					"ciphertext, and §4 requires the logs in unencrypted form")
			}
		}
	}
	sort.Strings(f)
	return f
}

// parseStatusCode enforces the example's "code is a three-digit string".
func parseStatusCode(s string) (int, error) {
	if len(s) != 3 {
		return 0, fmt.Errorf("want three digits")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a digit: %q", c)
		}
		n = n*10 + int(c-'0')
	}
	if n < 100 || n > 599 {
		return 0, fmt.Errorf("%d is not an HTTP status", n)
	}
	return n, nil
}

// BodyHasNoJSONNull is the guard behind §4.1.2's "empty string if none". The
// Go zero value already gives "", so the only way a null could appear is a
// caller marshalling a *string; keeping the rule here as a named check means
// the validator can state it rather than the encoder assuming it.
func BodyHasNoJSONNull(raw []byte) bool { return !strings.Contains(string(raw), `"body": null`) }
