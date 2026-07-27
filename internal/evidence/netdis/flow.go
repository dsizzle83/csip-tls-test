package netdis

import (
	"fmt"
	"net/netip"
)

// Endpoint is one side of a transport conversation.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// String renders an endpoint the way tcpdump and Wireshark filters do, with
// IPv6 literals bracketed.
func (e Endpoint) String() string {
	if !e.Addr.IsValid() {
		return fmt.Sprintf("?:%d", e.Port)
	}
	return netip.AddrPortFrom(e.Addr, e.Port).String()
}

// compare orders endpoints deterministically: by address, then by port. It has
// no meaning beyond giving StreamKey a stable canonical form.
func (e Endpoint) compare(o Endpoint) int {
	if c := e.Addr.Compare(o.Addr); c != 0 {
		return c
	}
	switch {
	case e.Port < o.Port:
		return -1
	case e.Port > o.Port:
		return 1
	}
	return 0
}

// FlowKey identifies one DIRECTION of a conversation: packets from Src to Dst.
type FlowKey struct {
	Src Endpoint
	Dst Endpoint
}

// Reverse returns the opposite direction of the same conversation.
func (f FlowKey) Reverse() FlowKey { return FlowKey{Src: f.Dst, Dst: f.Src} }

// String renders a direction as "src > dst".
func (f FlowKey) String() string { return f.Src.String() + " > " + f.Dst.String() }

// StreamKey identifies a conversation independent of direction. Both FlowKeys
// of a connection map to the same StreamKey, which is what lets an assertion
// name a stream once and then say which way the cited bytes were travelling.
type StreamKey struct {
	A Endpoint // the lower endpoint under Endpoint.compare
	B Endpoint
}

// Stream canonicalises a direction into its direction-independent stream key.
func (f FlowKey) Stream() StreamKey {
	if f.Src.compare(f.Dst) <= 0 {
		return StreamKey{A: f.Src, B: f.Dst}
	}
	return StreamKey{A: f.Dst, B: f.Src}
}

// String renders a stream as "a <> b" with the endpoints in canonical order, so
// the same conversation always prints the same way regardless of which packet
// happened to be seen first.
func (s StreamKey) String() string { return s.A.String() + " <> " + s.B.String() }

// DirIndex returns 0 for the A→B direction of the stream and 1 for B→A.
func (s StreamKey) DirIndex(f FlowKey) int {
	if f.Src == s.A {
		return 0
	}
	return 1
}

// Flow returns the FlowKey for direction dir (0 = A→B, 1 = B→A).
func (s StreamKey) Flow(dir int) FlowKey {
	if dir == 0 {
		return FlowKey{Src: s.A, Dst: s.B}
	}
	return FlowKey{Src: s.B, Dst: s.A}
}
