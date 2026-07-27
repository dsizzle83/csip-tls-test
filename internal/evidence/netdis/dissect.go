package netdis

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"csip-tls-test/internal/evidence/pcapng"
)

// LINKTYPE_* values this package dissects. The set is deliberately small: it is
// what the bench actually produces (Ethernet on enp1s0, Ethernet on lo, cooked
// captures from `-i any`, and the raw-IP variants a tunnel capture yields).
const (
	LinkTypeNull     = 0   // BSD loopback: 4-byte host-order address family
	LinkTypeEthernet = 1   // DIX Ethernet II
	LinkTypeRaw      = 101 // raw IP, version taken from the first nibble
	LinkTypeLoop     = 108 // OpenBSD loopback: 4-byte NETWORK-order address family
	LinkTypeLinuxSLL = 113 // Linux cooked capture v1 ("-i any" on older libpcap)
	LinkTypeIPv4     = 228 // raw IPv4
	LinkTypeIPv6     = 229 // raw IPv6
	LinkTypeSLL2     = 276 // Linux cooked capture v2 ("-i any" on libpcap >= 1.10)
)

// EtherType values that lead somewhere.
const (
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86DD
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88A8
	etherTypeVLAN9 = 0x9100
)

// IP protocol numbers.
const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// NetProto says which network-layer protocol a frame carried, if any.
type NetProto uint8

const (
	NetNone NetProto = iota
	NetIPv4
	NetIPv6
)

func (p NetProto) String() string {
	switch p {
	case NetIPv4:
		return "IPv4"
	case NetIPv6:
		return "IPv6"
	default:
		return "none"
	}
}

// TCPFlags is the TCP control-bit field.
type TCPFlags uint16

// TCP control bits, including the ECN/NS bits so a dissection never reports
// "unknown flags" on a frame a modern stack emitted.
const (
	FIN TCPFlags = 1 << iota
	SYN
	RST
	PSH
	ACK
	URG
	ECE
	CWR
	NS
)

// String renders flags in the conventional tcpdump-ish order.
func (f TCPFlags) String() string {
	names := []struct {
		bit  TCPFlags
		name string
	}{
		{SYN, "SYN"}, {ACK, "ACK"}, {PSH, "PSH"}, {FIN, "FIN"},
		{RST, "RST"}, {URG, "URG"}, {ECE, "ECE"}, {CWR, "CWR"}, {NS, "NS"},
	}
	out := ""
	for _, n := range names {
		if f&n.bit != 0 {
			if out != "" {
				out += "|"
			}
			out += n.name
		}
	}
	if out == "" {
		return "-"
	}
	return out
}

// Has reports whether every bit in want is set.
func (f TCPFlags) Has(want TCPFlags) bool { return f&want == want }

// TCPSegment is a dissected TCP header plus its payload.
type TCPSegment struct {
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32
	Ack       uint32
	Flags     TCPFlags
	Window    uint16
	HeaderLen int
	Options   []byte
	Payload   []byte
}

// UDPDatagram is a dissected UDP header plus its payload. UDP is dissected but
// not reassembled: the bench's DNS-SD discovery evidence lives here, and a
// datagram is its own message.
type UDPDatagram struct {
	SrcPort uint16
	DstPort uint16
	Length  int
	Payload []byte
}

// Frame is one dissected packet.
//
// A frame that carried no IP (ARP, LLDP, an 802.3 LLC frame) is NOT an error:
// Net is NetNone and Note says why dissection stopped. Errors are reserved for
// bytes that claim to be something they cannot be — a truncated header, an
// impossible length field — because those are the cases where guessing would
// fabricate evidence.
type Frame struct {
	Index      int
	Time       time.Time
	LinkType   uint16
	CaptureLen int
	OrigLen    int

	EtherType uint16   // 0 when the link layer has no ethertype
	VLANs     []uint16 // outermost first, empty when untagged

	Net        NetProto
	Src, Dst   netip.Addr
	IPProto    uint8
	TTL        uint8
	Fragmented bool   // an IPv4 fragment or an IPv6 fragment-header datagram
	FragOffset uint16 // in bytes
	Truncated  bool   // the capture kept fewer bytes than the IP header claims

	TCP *TCPSegment
	UDP *UDPDatagram

	Note string // why dissection stopped short, when it did
}

// Flow returns the direction key of a TCP or UDP frame. The second result is
// false for frames with no transport ports.
func (f *Frame) Flow() (FlowKey, bool) {
	switch {
	case f.TCP != nil:
		return FlowKey{
			Src: Endpoint{Addr: f.Src, Port: f.TCP.SrcPort},
			Dst: Endpoint{Addr: f.Dst, Port: f.TCP.DstPort},
		}, true
	case f.UDP != nil:
		return FlowKey{
			Src: Endpoint{Addr: f.Src, Port: f.UDP.SrcPort},
			Dst: Endpoint{Addr: f.Dst, Port: f.UDP.DstPort},
		}, true
	}
	return FlowKey{}, false
}

// DecodePacket dissects a captured packet.
func DecodePacket(p pcapng.Packet) (*Frame, error) {
	f, err := Decode(p.LinkType, p.Data)
	if err != nil {
		return nil, fmt.Errorf("frame %d: %w", p.Index, err)
	}
	f.Index = p.Index
	f.Time = p.Time
	f.OrigLen = p.OrigLen
	if p.Truncated() {
		f.Truncated = true
	}
	return f, nil
}

// Decode dissects one frame of the given link type.
func Decode(linkType uint16, data []byte) (*Frame, error) {
	f := &Frame{LinkType: linkType, CaptureLen: len(data), OrigLen: len(data)}
	rest, err := f.decodeLink(data)
	if err != nil {
		return nil, err
	}
	if rest == nil {
		return f, nil // link layer said "nothing above me"; Note explains
	}
	if err := f.decodeNetwork(rest); err != nil {
		return nil, err
	}
	return f, nil
}

// decodeLink strips the link header and returns the network-layer bytes, or nil
// when the frame carries no IP.
func (f *Frame) decodeLink(data []byte) ([]byte, error) {
	switch f.LinkType {
	case LinkTypeEthernet:
		return f.decodeEthernet(data)

	case LinkTypeNull, LinkTypeLoop:
		if len(data) < 4 {
			return nil, fmt.Errorf("netdis: %d-byte frame is too short for a 4-byte loopback header", len(data))
		}
		// LINKTYPE_NULL's family is in the CAPTURING HOST's byte order, which is
		// not recorded anywhere in the file. Trying little-endian first and then
		// big-endian is what libpcap's own printers do; LINKTYPE_LOOP (108) is
		// the same header pinned to network order.
		fam := binary.LittleEndian.Uint32(data[:4])
		if f.LinkType == LinkTypeLoop || !knownAddressFamily(fam) {
			fam = binary.BigEndian.Uint32(data[:4])
		}
		switch {
		case fam == afINET:
			f.EtherType = etherTypeIPv4
		case isAFINET6(fam):
			f.EtherType = etherTypeIPv6
		default:
			f.Note = fmt.Sprintf("loopback address family %d is not IPv4 or IPv6", fam)
			return nil, nil
		}
		return data[4:], nil

	case LinkTypeRaw, LinkTypeIPv4, LinkTypeIPv6:
		if len(data) == 0 {
			return nil, fmt.Errorf("netdis: raw-IP frame is empty")
		}
		switch {
		case f.LinkType == LinkTypeIPv4:
			f.EtherType = etherTypeIPv4
		case f.LinkType == LinkTypeIPv6:
			f.EtherType = etherTypeIPv6
		case data[0]>>4 == 4:
			f.EtherType = etherTypeIPv4
		case data[0]>>4 == 6:
			f.EtherType = etherTypeIPv6
		default:
			f.Note = fmt.Sprintf("raw-IP frame starts with IP version nibble %d", data[0]>>4)
			return nil, nil
		}
		return data, nil

	case LinkTypeLinuxSLL:
		// packet type(2) ARPHRD(2) addr len(2) addr(8) protocol(2)
		if len(data) < 16 {
			return nil, fmt.Errorf("netdis: %d-byte frame is too short for a 16-byte Linux SLL header", len(data))
		}
		f.EtherType = binary.BigEndian.Uint16(data[14:16])
		return f.afterEtherType(data[16:])

	case LinkTypeSLL2:
		// protocol(2) reserved(2) ifindex(4) ARPHRD(2) packet type(1) addr len(1) addr(8)
		if len(data) < 20 {
			return nil, fmt.Errorf("netdis: %d-byte frame is too short for a 20-byte Linux SLL2 header", len(data))
		}
		f.EtherType = binary.BigEndian.Uint16(data[0:2])
		return f.afterEtherType(data[20:])

	default:
		f.Note = fmt.Sprintf("unsupported link type %d", f.LinkType)
		return nil, nil
	}
}

func (f *Frame) decodeEthernet(data []byte) ([]byte, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("netdis: %d-byte frame is too short for a 14-byte Ethernet header", len(data))
	}
	et := binary.BigEndian.Uint16(data[12:14])
	rest := data[14:]
	// Up to three stacked VLAN tags (802.1Q inside 802.1ad inside a provider
	// tag is the deepest anything on this bench could plausibly produce).
	for tags := 0; tags < 3; tags++ {
		if et != etherTypeVLAN && et != etherTypeQinQ && et != etherTypeVLAN9 {
			break
		}
		if len(rest) < 4 {
			return nil, fmt.Errorf("netdis: VLAN tag is truncated after %d bytes", len(rest))
		}
		f.VLANs = append(f.VLANs, binary.BigEndian.Uint16(rest[0:2])&0x0FFF)
		et = binary.BigEndian.Uint16(rest[2:4])
		rest = rest[4:]
	}
	f.EtherType = et
	return f.afterEtherType(rest)
}

// afterEtherType routes on a resolved ethertype.
func (f *Frame) afterEtherType(rest []byte) ([]byte, error) {
	switch f.EtherType {
	case etherTypeIPv4, etherTypeIPv6:
		return rest, nil
	default:
		if f.EtherType < 1536 {
			f.Note = fmt.Sprintf("802.3 length field %d (LLC frame, not Ethernet II)", f.EtherType)
		} else {
			f.Note = fmt.Sprintf("ethertype 0x%04X is not IP", f.EtherType)
		}
		return nil, nil
	}
}

// Address-family constants seen in LINKTYPE_NULL headers. AF_INET is 2
// everywhere; AF_INET6 is famously not (Linux 10, FreeBSD 28, macOS/Darwin 30,
// NetBSD/OpenBSD 24/26).
const afINET = 2

func isAFINET6(fam uint32) bool {
	switch fam {
	case 10, 23, 24, 26, 28, 30:
		return true
	}
	return false
}

func knownAddressFamily(fam uint32) bool { return fam == afINET || isAFINET6(fam) }

func (f *Frame) decodeNetwork(data []byte) error {
	switch f.EtherType {
	case etherTypeIPv4:
		return f.decodeIPv4(data)
	case etherTypeIPv6:
		return f.decodeIPv6(data)
	}
	return nil
}

func (f *Frame) decodeIPv4(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("netdis: %d bytes is too short for a 20-byte IPv4 header", len(data))
	}
	if v := data[0] >> 4; v != 4 {
		return fmt.Errorf("netdis: IPv4 header carries version %d", v)
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 {
		return fmt.Errorf("netdis: IPv4 header length field says %d bytes, below the 20-byte minimum", ihl)
	}
	if ihl > len(data) {
		return fmt.Errorf("netdis: IPv4 header length %d exceeds the %d captured bytes", ihl, len(data))
	}
	total := int(binary.BigEndian.Uint16(data[2:4]))
	if total != 0 && total < ihl {
		return fmt.Errorf("netdis: IPv4 total length %d is below its own header length %d", total, ihl)
	}
	f.Net = NetIPv4
	f.TTL = data[8]
	f.IPProto = data[9]
	f.Src = netip.AddrFrom4([4]byte(data[12:16]))
	f.Dst = netip.AddrFrom4([4]byte(data[16:20]))

	frag := binary.BigEndian.Uint16(data[6:8])
	moreFragments := frag&0x2000 != 0
	f.FragOffset = (frag & 0x1FFF) * 8
	f.Fragmented = moreFragments || f.FragOffset > 0

	// A total length of zero means TCP segmentation offload handed libpcap a
	// super-frame; a total length past the captured bytes means the capture was
	// snaplen-truncated. Both are normal, and both mean the payload we have is
	// what the file holds — not what the header claims.
	end := len(data)
	if total != 0 && total < end {
		end = total
	} else if total > len(data) {
		f.Truncated = true
	}
	payload := data[ihl:end]

	if f.Fragmented {
		f.Note = fmt.Sprintf("IPv4 fragment (offset %d, more=%t): not reassembled", f.FragOffset, moreFragments)
		return nil
	}
	return f.decodeTransport(payload)
}

// IPv6 extension header numbers.
const (
	ipv6HopByHop  = 0
	ipv6Routing   = 43
	ipv6Fragment  = 44
	ipv6ESP       = 50
	ipv6AH        = 51
	ipv6NoNextHdr = 59
	ipv6DestOpts  = 60
	ipv6Mobility  = 135
)

func (f *Frame) decodeIPv6(data []byte) error {
	if len(data) < 40 {
		return fmt.Errorf("netdis: %d bytes is too short for a 40-byte IPv6 header", len(data))
	}
	if v := data[0] >> 4; v != 6 {
		return fmt.Errorf("netdis: IPv6 header carries version %d", v)
	}
	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))
	f.Net = NetIPv6
	f.TTL = data[7]
	f.Src = netip.AddrFrom16([16]byte(data[8:24]))
	f.Dst = netip.AddrFrom16([16]byte(data[24:40]))

	end := 40 + payloadLen
	if payloadLen == 0 || end > len(data) {
		if end > len(data) {
			f.Truncated = true
		}
		end = len(data)
	}
	rest := data[40:end]
	next := data[6]

	// Walk the extension-header chain. The bound is not decoration: a crafted
	// capture can point a chain at itself, and an unbounded walk would hang the
	// verifier a third party is running.
	for hops := 0; hops < 16; hops++ {
		switch next {
		case ipv6HopByHop, ipv6Routing, ipv6DestOpts, ipv6Mobility:
			if len(rest) < 8 {
				return fmt.Errorf("netdis: IPv6 extension header %d is truncated at %d bytes", next, len(rest))
			}
			extLen := (int(rest[1]) + 1) * 8
			if extLen > len(rest) {
				return fmt.Errorf("netdis: IPv6 extension header %d claims %d bytes, %d remain", next, extLen, len(rest))
			}
			next, rest = rest[0], rest[extLen:]
		case ipv6AH:
			if len(rest) < 8 {
				return fmt.Errorf("netdis: IPv6 authentication header is truncated at %d bytes", len(rest))
			}
			extLen := (int(rest[1]) + 2) * 4
			if extLen > len(rest) {
				return fmt.Errorf("netdis: IPv6 authentication header claims %d bytes, %d remain", extLen, len(rest))
			}
			next, rest = rest[0], rest[extLen:]
		case ipv6Fragment:
			if len(rest) < 8 {
				return fmt.Errorf("netdis: IPv6 fragment header is truncated at %d bytes", len(rest))
			}
			off := binary.BigEndian.Uint16(rest[2:4])
			f.FragOffset = off &^ 0x7
			more := off&0x1 != 0
			f.Fragmented = true
			f.IPProto = rest[0]
			f.Note = fmt.Sprintf("IPv6 fragment (offset %d, more=%t): not reassembled", f.FragOffset, more)
			return nil
		case ipv6ESP:
			f.IPProto = ipv6ESP
			f.Note = "IPv6 ESP payload: encrypted at the network layer, no transport dissection"
			return nil
		case ipv6NoNextHdr:
			f.IPProto = ipv6NoNextHdr
			f.Note = "IPv6 chain ends with no next header"
			return nil
		default:
			f.IPProto = next
			return f.decodeTransport(rest)
		}
	}
	return fmt.Errorf("netdis: IPv6 extension header chain exceeds 16 headers")
}

func (f *Frame) decodeTransport(data []byte) error {
	switch f.IPProto {
	case ipProtoTCP:
		return f.decodeTCP(data)
	case ipProtoUDP:
		return f.decodeUDP(data)
	default:
		f.Note = fmt.Sprintf("IP protocol %d is not TCP or UDP", f.IPProto)
		return nil
	}
}

func (f *Frame) decodeTCP(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("netdis: %d bytes is too short for a 20-byte TCP header", len(data))
	}
	off := int(data[12]>>4) * 4
	if off < 20 {
		return fmt.Errorf("netdis: TCP data offset says %d bytes, below the 20-byte minimum", off)
	}
	if off > len(data) {
		// Snaplen truncation can cut into the options; that is a truncated
		// capture, not a malformed packet, but there is no payload to speak of.
		f.Truncated = true
		off = len(data)
	}
	seg := &TCPSegment{
		SrcPort:   binary.BigEndian.Uint16(data[0:2]),
		DstPort:   binary.BigEndian.Uint16(data[2:4]),
		Seq:       binary.BigEndian.Uint32(data[4:8]),
		Ack:       binary.BigEndian.Uint32(data[8:12]),
		Flags:     TCPFlags(data[13]) | TCPFlags(data[12]&0x01)<<8,
		Window:    binary.BigEndian.Uint16(data[14:16]),
		HeaderLen: off,
	}
	if off > 20 {
		seg.Options = data[20:off]
	}
	seg.Payload = data[off:]
	f.TCP = seg
	return nil
}

func (f *Frame) decodeUDP(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("netdis: %d bytes is too short for an 8-byte UDP header", len(data))
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	end := len(data)
	if length >= 8 && length < end {
		end = length
	} else if length > len(data) {
		f.Truncated = true
	}
	f.UDP = &UDPDatagram{
		SrcPort: binary.BigEndian.Uint16(data[0:2]),
		DstPort: binary.BigEndian.Uint16(data[2:4]),
		Length:  length,
		Payload: data[8:end],
	}
	return nil
}
