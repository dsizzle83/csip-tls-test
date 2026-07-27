package suitemodbusserver

// appstream.go is the citation half of this suite: it turns the run's capture
// back into the Modbus ADUs that crossed the wire, with every ADU carrying the
// capture frame numbers its bytes actually arrived in.
//
// This is the piece that makes the suite's output trustworthy rather than
// merely plausible. The live phase already knows what it sent and what it read
// back from its socket — but a report resting on that is a report resting on
// its own memory. The claim a certification reviewer can act on is "these bytes
// were on the wire, in these frames, and here is the digest". Re-deriving the
// exchange from the capture, independently of the live phase's recollection,
// and then comparing the two, is what closes the gap: when they disagree, the
// suite says so and refuses the PASS.
//
// # Two paths to the same bytes
//
// Plain Modbus/TCP: the reassembled TCP direction IS the application stream,
// and netdis already tracks byte-offset to frame.
//
// mbaps: the reassembled direction is TLS records. The stream must be parsed
// into records (tlsdis), decrypted with the run's NSS key log (tlsdecrypt), and
// the recovered plaintext concatenated — at which point the byte-offset to
// frame mapping is no longer netdis's, because the plaintext offsets are not
// the ciphertext offsets. So this file keeps its own segment table: each
// recovered record contributes one [start,end) span of the plaintext stream and
// the frames that record occupied.
//
// Failure is loud in both paths. A record that will not decrypt aborts the
// reconstruction with the error tlsdecrypt produced (which names the side, the
// record, the sequence number and the frames) and the calling check emits a
// SKIP carrying it. Partial plaintext is never returned: a half-decrypted
// stream would let a check assert on an ADU whose neighbours it could not read,
// which is exactly the kind of quiet incompleteness this tool exists to
// prevent.

import (
	"encoding/binary"
	"fmt"
	"sort"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// segment maps a half-open range of a reconstructed application stream to the
// capture frames its bytes arrived in.
type segment struct {
	start, end int
	frames     []int
}

// appStream is one direction's application-layer bytes with frame provenance.
type appStream struct {
	// Flow names the direction, e.g. "69.0.0.20:51422 > 69.0.0.2:802".
	Flow string
	// Data is the reconstructed application byte stream.
	Data []byte
	// Encrypted reports whether the bytes were recovered from TLS records.
	Encrypted bool

	segs []segment
	// dir is the underlying reassembled direction, kept so a plain-transport
	// citation can use CiteBytes over the real stream offsets.
	dir *netdis.Direction
}

// Len is the reconstructed stream length.
func (a *appStream) Len() int {
	if a == nil {
		return 0
	}
	return len(a.Data)
}

// framesFor returns the capture frames carrying the half-open byte range,
// ascending and de-duplicated.
func (a *appStream) framesFor(start, end int) []int {
	if a == nil || start >= end {
		return nil
	}
	if !a.Encrypted && a.dir != nil {
		return a.dir.Bytes.PacketsFor(start, end)
	}
	seen := map[int]bool{}
	var out []int
	for _, s := range a.segs {
		if s.end <= start || s.start >= end {
			continue
		}
		for _, f := range s.frames {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Ints(out)
	return out
}

// observedADU is one MBAP frame recovered from the capture.
type observedADU struct {
	TID    uint16
	Unit   uint8
	PDU    []byte
	Start  int // byte offset of the ADU's first header byte in the app stream
	End    int // one past its last byte
	Frames []int
}

// FC is the ADU's function code byte, including the 0x80 exception bit when
// the ADU is an exception response.
func (a observedADU) FC() byte {
	if len(a.PDU) == 0 {
		return 0
	}
	return a.PDU[0]
}

// IsException reports whether the ADU is an exception response.
func (a observedADU) IsException() bool { return a.FC()&0x80 != 0 }

// ExceptionCode returns the exception code byte, or 0.
func (a observedADU) ExceptionCode() byte {
	if a.IsException() && len(a.PDU) >= 2 {
		return a.PDU[1]
	}
	return 0
}

// String renders the ADU the way a Modbus PDU log does.
func (a observedADU) String() string {
	return fmt.Sprintf("tid=0x%04x unit=%d pdu=% x frames=%v", a.TID, a.Unit, a.PDU, a.Frames)
}

// parseADUs splits an application stream into MBAP frames.
//
// The parse is strict in the same way lexa-proto/mbap's decoder is — protocol
// identifier zero, length in range — because a stream that does not parse
// strictly is a stream whose frame boundaries are guesses, and an ADU cited
// from a guessed boundary is not evidence. A trailing partial frame is
// returned as a remainder rather than an error: TCP-2 deliberately produces
// one.
func parseADUs(a *appStream) (adus []observedADU, remainder int, err error) {
	data := a.Data
	off := 0
	for off+7 <= len(data) {
		pid := binary.BigEndian.Uint16(data[off+2 : off+4])
		length := int(binary.BigEndian.Uint16(data[off+4 : off+6]))
		if pid != 0 {
			return adus, len(data) - off, fmt.Errorf(
				"suitemodbusserver: %s: protocol identifier 0x%04x at stream offset %d, want 0 — "+
					"the reconstructed stream is not MBAP-aligned, so no ADU in it can be cited",
				a.Flow, pid, off)
		}
		if length < 3 || length > 254 {
			return adus, len(data) - off, fmt.Errorf(
				"suitemodbusserver: %s: MBAP length %d at stream offset %d is outside [3,254]",
				a.Flow, length, off)
		}
		end := off + 6 + length
		if end > len(data) {
			// A complete header promising bytes that never arrived.
			return adus, len(data) - off, nil
		}
		adus = append(adus, observedADU{
			TID:    binary.BigEndian.Uint16(data[off : off+2]),
			Unit:   data[off+6],
			PDU:    append([]byte(nil), data[off+7:end]...),
			Start:  off,
			End:    end,
			Frames: a.framesFor(off, end),
		})
		off = end
	}
	return adus, len(data) - off, nil
}

// conversation is both directions of one session's application layer, plus the
// ADUs recovered from each.
type conversation struct {
	Request  *appStream
	Response *appStream
	// Requests and Responses are the recovered ADUs in wire order.
	Requests  []observedADU
	Responses []observedADU
	// ReqRemainder / RespRemainder are the trailing bytes that did not form a
	// complete ADU. TCP-2 expects a nonzero request remainder; anywhere else it
	// is a finding.
	ReqRemainder  int
	RespRemainder int
	// TLSRecords counts the records seen per direction when encrypted, so a
	// framing claim (TCP-3) can be made at the record layer as well as the
	// segment layer.
	ReqRecords, RespRecords int
	// ReqParseErr / RespParseErr record a direction that could not be split
	// into MBAP frames. They are carried rather than returned because TCP-2
	// DELIBERATELY desynchronises the request direction: that check has to be
	// able to look at the response direction of a conversation whose request
	// direction is, by design, no longer frame-aligned. Every other check
	// refuses to cite anything when either is set.
	ReqParseErr, RespParseErr error
}

// responseTo returns the response ADU echoing tid.
func (c *conversation) responseTo(tid uint16) (observedADU, bool) {
	for _, a := range c.Responses {
		if a.TID == tid {
			return a, true
		}
	}
	return observedADU{}, false
}

// requestWithTID returns the request ADU carrying tid.
func (c *conversation) requestWithTID(tid uint16) (observedADU, bool) {
	for _, a := range c.Requests {
		if a.TID == tid {
			return a, true
		}
	}
	return observedADU{}, false
}

// AllFrames returns every frame either direction's ADUs occupied.
func (c *conversation) AllFrames() []int {
	seen := map[int]bool{}
	var out []int
	for _, set := range [][]observedADU{c.Requests, c.Responses} {
		for _, a := range set {
			for _, f := range a.Frames {
				if !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

// reconstruct rebuilds the application layer of the session's conversation from
// the capture.
//
// It is the single entry point every Cite callback in this suite goes through,
// so the "did the wire actually show this?" question is answered the same way
// everywhere.
func reconstruct(ev *certify.Evidence, s *session) (*conversation, error) {
	if !ev.HasFrames() {
		return nil, fmt.Errorf("no capture frames were attributed to this test case")
	}
	st, err := streamFor(ev, s)
	if err != nil {
		return nil, err
	}
	toDUT := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: s.Local.Addr(), Port: s.Local.Port()},
		Dst: netdis.Endpoint{Addr: s.Remote.Addr(), Port: s.Remote.Port()},
	})
	fromDUT := st.ByFlow(netdis.FlowKey{
		Src: netdis.Endpoint{Addr: s.Remote.Addr(), Port: s.Remote.Port()},
		Dst: netdis.Endpoint{Addr: s.Local.Addr(), Port: s.Local.Port()},
	})
	if toDUT == nil || fromDUT == nil {
		return nil, fmt.Errorf("the capture holds only one direction of %s <> %s", s.Local, s.Remote)
	}

	conv := &conversation{}
	if !s.Encrypted() {
		conv.Request = &appStream{Flow: toDUT.Flow.String(), Data: toDUT.Bytes.Bytes(), dir: toDUT}
		conv.Response = &appStream{Flow: fromDUT.Flow.String(), Data: fromDUT.Bytes.Bytes(), dir: fromDUT}
	} else {
		if ev.KeyLog == nil {
			return nil, fmt.Errorf("the conversation ran inside TLS and the run exported no NSS key log, " +
				"so the capture holds ciphertext only (build with -tags keylog and pass -keylog)")
		}
		client, err := tlsdis.ParseDirection(toDUT.Bytes.Bytes(), toDUT.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse TLS records sent to the DUT: %w", err)
		}
		server, err := tlsdis.ParseDirection(fromDUT.Bytes.Bytes(), fromDUT.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse TLS records received from the DUT: %w", err)
		}
		params, err := tlsdecrypt.ParamsFromHandshake(client, server)
		if err != nil {
			return nil, err
		}
		sess, err := tlsdecrypt.New(params, ev.KeyLog)
		if err != nil {
			return nil, err
		}
		conv.ReqRecords = len(client.Stream.Records)
		conv.RespRecords = len(server.Stream.Records)
		conv.Request, err = decryptSide(sess, tlsdecrypt.Client, client, toDUT)
		if err != nil {
			return nil, err
		}
		conv.Response, err = decryptSide(sess, tlsdecrypt.Server, server, fromDUT)
		if err != nil {
			return nil, err
		}
	}

	conv.Requests, conv.ReqRemainder, conv.ReqParseErr = parseADUs(conv.Request)
	conv.Responses, conv.RespRemainder, conv.RespParseErr = parseADUs(conv.Response)
	return conv, nil
}

// decryptSide recovers one direction's application data.
func decryptSide(sess *tlsdecrypt.Session, side tlsdecrypt.Side, dir *tlsdis.Direction, nd *netdis.Direction) (*appStream, error) {
	out := &appStream{Flow: nd.Flow.String(), Encrypted: true}
	for _, rec := range dir.Stream.Records {
		p, err := sess.Decrypt(side, rec)
		if err != nil {
			return nil, err
		}
		if p.Type != tlsdis.ContentApplicationData || len(p.Data) == 0 {
			continue
		}
		start := len(out.Data)
		out.Data = append(out.Data, p.Data...)
		out.segs = append(out.segs, segment{
			start:  start,
			end:    len(out.Data),
			frames: append([]int(nil), p.Record.Packets...),
		})
	}
	return out, nil
}

// recordSpanFor returns the TLS records (by index) that carry a half-open range
// of the reconstructed plaintext stream, along with the capture frames those
// records occupied. It is what TCP-3 asserts on: a request that arrived in more
// than one record, or more than one frame, was genuinely split on the wire.
func (a *appStream) recordSpanFor(start, end int) (records int, frames []int) {
	if a == nil {
		return 0, nil
	}
	if !a.Encrypted {
		return 0, a.framesFor(start, end)
	}
	seen := map[int]bool{}
	for _, s := range a.segs {
		if s.end <= start || s.start >= end {
			continue
		}
		records++
		for _, f := range s.frames {
			if !seen[f] {
				seen[f] = true
				frames = append(frames, f)
			}
		}
	}
	sort.Ints(frames)
	return records, frames
}

// streamFor finds the conversation belonging to this session.
//
// It matches on BOTH endpoints rather than asking the framework for "the
// conversation with the DUT", because one test case legitimately opens more
// than one connection to the same remote — TCP-2 does, to demonstrate recovery
// after a truncated request — and in that case the framework refuses to guess.
// The session knows its own local port; that is the disambiguator.
func streamFor(ev *certify.Evidence, s *session) (*netdis.Stream, error) {
	want := netdis.FlowKey{
		Src: netdis.Endpoint{Addr: s.Local.Addr(), Port: s.Local.Port()},
		Dst: netdis.Endpoint{Addr: s.Remote.Addr(), Port: s.Remote.Port()},
	}.Stream()
	for _, st := range ev.Streams() {
		if st.Key == want {
			return st, nil
		}
	}
	return nil, fmt.Errorf("the capture holds no attributed conversation %s <> %s", s.Local, s.Remote)
}
