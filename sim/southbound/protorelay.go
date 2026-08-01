package sim

// protorelay.go — a second, independent MBAP-aware relay for the two
// framing faults that manipulate HOW response bytes are DELIVERED on the
// wire, as opposed to wire.go's Mangler (which manipulates WHAT the
// delivered bytes say, or which id/txn they wear):
//
//	segment_response   one Modbus/TCP response is written to the client in
//	                    TWO separate socket writes, split at an arbitrary
//	                    byte offset, so a client that (wrongly) assumes "one
//	                    read call == one ADU" — true on loopback almost
//	                    always, which is exactly why §2.8.2 PROT-2's
//	                    reassembly path goes untested otherwise — is forced
//	                    to actually reassemble. See PROT-2#2.
//	short_response      a response is written with its MBAP length field
//	                    still promising the full PDU while fewer bytes than
//	                    that are actually sent — and the connection is left
//	                    open, so the client is genuinely waiting on bytes
//	                    that will never come. See PROT-1#2.
//
// It is a SEPARATE relay/port from -mangle's Mangler rather than two new
// cases added to wire.go, purely for change-isolation on a shared working
// tree (see the commit message this file landed in). It reuses wire.go's
// readMBAPFrame/mbapHeaderLen directly (same package) rather than
// re-parsing MBAP a third time.
//
// Interposition is OPT-IN (modsim -protofault), mirroring -mangle: a shared
// live bench is never silently reframed, and OFF is a literal direct bind
// with these two kinds simply unavailable — see modsim/main.go. Combining
// -mangle and -protofault in the same process is not yet supported (main.go
// refuses at startup) — nothing in this QA batch's scope needs both
// relays interposed at once.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// FaultSegmentResponse splits each response into two socket writes at
// SplitAfter bytes (default: right after the 7-byte MBAP header, so header
// and PDU land in separate writes — the split most likely to actually
// survive as two TCP segments rather than being re-coalesced by the kernel).
const FaultSegmentResponse FaultKind = "segment_response"

// FaultShortResponse writes only TruncateBytes bytes of PDU while leaving
// the MBAP length field promising the full response, and does not close the
// connection afterward — see PROT-1's "partial response" (§2.8.1 does not
// define the term; this is the structurally-truncated reading wire.go's
// truncate_response already gives -mangle, offered here without needing a
// second, unrelated relay's other four kinds).
const FaultShortResponse FaultKind = "short_response"

// protoFaultKinds is the set this file owns.
var protoFaultKinds = map[FaultKind]bool{
	FaultSegmentResponse: true,
	FaultShortResponse:   true,
}

// protoSpec is the POST /fault body for the two kinds this file owns.
type protoSpec struct {
	Kind          FaultKind `json:"kind"`
	Clear         bool      `json:"clear,omitempty"`
	SplitAfter    int       `json:"split_after,omitempty"`    // segment_response: byte offset to split at (default: mbapHeaderLen)
	TruncateBytes int       `json:"truncate_bytes,omitempty"` // short_response: PDU bytes to actually send (default 2)
}

// ProtoRelay is a raw MBAP-framing TCP relay, structurally the same shape as
// wire.go's Mangler: it forwards the request direction verbatim and applies
// armed faults only to the response direction.
type ProtoRelay struct {
	listenAddr string
	upstream   string

	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu         sync.Mutex
	segment    bool
	splitAfter int
	short      bool
	truncBytes int

	frames  uint64
	applied map[FaultKind]uint64
}

// ProtoRelayStats is this relay's own account of what it relayed and
// mangled — the same evidence-not-inference pattern as wire.go's WireStats.
type ProtoRelayStats struct {
	Frames  uint64            `json:"frames"`
	Applied map[string]uint64 `json:"applied,omitempty"`
}

// NewProtoRelay starts a relay on listenAddr forwarding to upstream (both
// host:port). It returns as soon as the listener is bound, so a caller may
// dial immediately.
func NewProtoRelay(listenAddr, upstream string) (*ProtoRelay, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("sim: protorelay listen %s: %w", listenAddr, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &ProtoRelay{
		listenAddr: ln.Addr().String(),
		upstream:   upstream,
		ln:         ln,
		cancel:     cancel,
		applied:    make(map[FaultKind]uint64),
	}
	p.wg.Add(1)
	go p.serve(ctx)
	return p, nil
}

// Addr returns the address the relay is listening on.
func (p *ProtoRelay) Addr() string { return p.listenAddr }

// Close stops the relay and waits for its goroutines.
func (p *ProtoRelay) Close() {
	p.cancel()
	_ = p.ln.Close()
	p.wg.Wait()
}

// Stats snapshots the relay's counters.
func (p *ProtoRelay) Stats() ProtoRelayStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := ProtoRelayStats{Frames: p.frames, Applied: make(map[string]uint64, len(p.applied))}
	for k, v := range p.applied {
		out.Applied[string(k)] = v
	}
	return out
}

func (p *ProtoRelay) serve(ctx context.Context) {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(ctx, conn)
		}()
	}
}

// handle relays one client connection. The request direction is a verbatim
// io.Copy — the device must see exactly the bytes the client sent. Only the
// response direction is framed and, per the armed fault, written to the
// client in whatever shape that fault calls for.
func (p *ProtoRelay) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		log.Printf("[protorelay] upstream %s unreachable: %v", p.upstream, err)
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { p.pumpResponses(up, client); done <- struct{}{} }()

	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = up.Close()
	_ = client.Close()
	<-done
}

// pumpResponses frames the upstream's response stream one ADU at a time and
// writes each to the client via writeFrame. A framing error ends the relay
// for this connection rather than guessing.
func (p *ProtoRelay) pumpResponses(up, client net.Conn) {
	for {
		frame, err := readMBAPFrame(up) // wire.go — same package, reused rather than re-parsed
		if err != nil {
			return
		}
		p.mu.Lock()
		p.frames++
		p.mu.Unlock()
		if err := p.writeFrame(client, frame); err != nil {
			return
		}
	}
}

// writeFrame is the pure core pumpResponses drives: given one well-formed
// response frame, it writes it to w according to whichever fault is armed
// (or unchanged, with none armed). Factored out so tests can drive it
// against a recording io.Writer instead of racing real TCP segment
// coalescing, which is not a reliable way to prove "two writes happened."
func (p *ProtoRelay) writeFrame(w io.Writer, frame []byte) error {
	p.mu.Lock()
	short, truncBytes := p.short, p.truncBytes
	seg, splitAfter := p.segment, p.splitAfter
	p.mu.Unlock()

	switch {
	case short:
		keep := mbapHeaderLen + truncBytes
		if keep < mbapHeaderLen {
			keep = mbapHeaderLen
		}
		if keep > len(frame) {
			keep = len(frame)
		}
		// The length field is left exactly as the upstream server wrote it
		// — still promising the full PDU — only the WRITE is cut short.
		if _, err := w.Write(frame[:keep]); err != nil {
			return err
		}
		p.count(FaultShortResponse)
		return nil

	case seg:
		n := splitAfter
		if n <= 0 || n >= len(frame) {
			n = len(frame) / 2
		}
		if n <= 0 {
			n = 1
		}
		if _, err := w.Write(frame[:n]); err != nil {
			return err
		}
		if _, err := w.Write(frame[n:]); err != nil {
			return err
		}
		p.count(FaultSegmentResponse)
		return nil

	default:
		_, err := w.Write(frame)
		return err
	}
}

func (p *ProtoRelay) count(k FaultKind) {
	p.mu.Lock()
	if p.applied == nil {
		p.applied = make(map[FaultKind]uint64)
	}
	p.applied[k]++
	p.mu.Unlock()
}

// ApplyFault arms or clears one of this relay's two kinds. It reports
// handled=false for a kind it does not own, mirroring wire.go's Mangler so
// a sim binary can offer both relays through the one POST /fault endpoint.
func (p *ProtoRelay) ApplyFault(body []byte) (handled bool, err error) {
	var spec protoSpec
	if e := json.Unmarshal(body, &spec); e != nil {
		return false, fmt.Errorf("fault: %w", e)
	}
	if !protoFaultKinds[spec.Kind] {
		return false, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch spec.Kind {
	case FaultSegmentResponse:
		if spec.Clear {
			p.segment = false
			break
		}
		n := spec.SplitAfter
		if n <= 0 {
			n = mbapHeaderLen
		}
		p.segment, p.splitAfter = true, n

	case FaultShortResponse:
		if spec.Clear {
			p.short = false
			break
		}
		n := spec.TruncateBytes
		if n <= 0 {
			n = 2 // the function code and the byte count survive; the data does not
		}
		p.short, p.truncBytes = true, n
	}
	log.Printf("[protorelay] %s: %s armed=%v", p.listenAddr, spec.Kind, !spec.Clear)
	return true, nil
}

// protoKindNames lists this relay's kinds, for a sim binary's error message
// when a proto fault is requested but no relay is interposed.
func protoKindNames() string {
	names := make([]string, 0, len(protoFaultKinds))
	for k := range protoFaultKinds {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ErrNoProtoRelay is returned by a sim that was asked for a proto-fault kind
// while running without an interposed ProtoRelay: restart with -protofault.
var ErrNoProtoRelay = errors.New("segment/truncate framing faults need an interposed relay: restart the sim with -protofault (kinds: " + protoKindNames() + ")")

// ProtoFaultRequested reports whether a POST /fault body names one of this
// file's kinds, the same way wire.go's WireFaultRequested does for its own.
func ProtoFaultRequested(body []byte) bool {
	var spec protoSpec
	if json.Unmarshal(body, &spec) != nil {
		return false
	}
	return protoFaultKinds[spec.Kind]
}
