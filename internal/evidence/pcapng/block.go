package pcapng

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// pcapng block types (PCAP Next Generation Capture File Format, draft-tuexen).
// Only the four that carry structure the evidence engine needs are handled;
// everything else is skipped by length, which is the format's whole point.
const (
	blockSectionHeader    = 0x0A0D0D0A
	blockInterfaceDesc    = 0x00000001
	blockSimplePacket     = 0x00000003
	blockEnhancedPacket   = 0x00000006
	blockNameResolution   = 0x00000004
	blockInterfaceStats   = 0x00000005
	blockDecryptionSecret = 0x0000000A
)

// byteOrderMagic is the SHB field that settles the section's endianness.
const byteOrderMagic = 0x1A2B3C4D

// optEndOfOpt terminates an option list; optIfTsResol (9) is the only option
// whose value changes how packets are interpreted.
const (
	optEndOfOpt  = 0
	optIfName    = 2
	optIfTsResol = 9
)

// ngInterface is one Interface Description Block: the link type every packet
// on that interface is dissected as, and the timestamp resolution every
// timestamp on it is scaled by.
type ngInterface struct {
	LinkType  uint16
	SnapLen   uint32
	Name      string
	PerSecond uint64 // timestamp ticks per second, from if_tsresol (default 1e6)
}

// ngState is the reader's position within the current pcapng section. A file
// may contain several sections, each with its own byte order and its own
// interface list, so both reset on every Section Header Block.
type ngState struct {
	bo         binary.ByteOrder
	major      uint16
	minor      uint16
	interfaces []ngInterface
}

// nextNG walks blocks until one yields a packet.
func (r *Reader) nextNG() (Packet, error) {
	for {
		raw, err := r.read(4, "pcapng block type")
		if err != nil {
			return Packet{}, err // io.EOF here is the clean end of the file
		}

		isSHB := raw[0] == 0x0A && raw[1] == 0x0D && raw[2] == 0x0D && raw[3] == 0x0A
		if !isSHB && r.ng.bo == nil {
			return Packet{}, fmt.Errorf("pcapng: first block is type 0x%X, want a Section Header Block", raw)
		}

		lenRaw, err := r.read(4, "pcapng block length")
		if err != nil {
			return Packet{}, unexpected(err)
		}

		var (
			bo       = r.ng.bo
			bodyHead []byte // bytes of the body already consumed (SHB byte-order magic)
		)
		if isSHB {
			bodyHead, err = r.read(4, "pcapng byte-order magic")
			if err != nil {
				return Packet{}, unexpected(err)
			}
			switch {
			case binary.LittleEndian.Uint32(bodyHead) == byteOrderMagic:
				bo = binary.LittleEndian
			case binary.BigEndian.Uint32(bodyHead) == byteOrderMagic:
				bo = binary.BigEndian
			default:
				return Packet{}, fmt.Errorf("pcapng: bad byte-order magic 0x%X in Section Header Block", bodyHead)
			}
		}

		total := int(bo.Uint32(lenRaw))
		// 12 = type(4) + length(4) + trailing length(4); the format also
		// mandates 32-bit alignment of the whole block.
		if total < 12 || total%4 != 0 {
			return Packet{}, fmt.Errorf("pcapng: block 0x%X declares an impossible length %d", raw, total)
		}
		if total > MaxBlockLen {
			return Packet{}, fmt.Errorf("pcapng: block 0x%X declares length %d over the %d-byte limit", raw, total, MaxBlockLen)
		}

		body, err := r.read(total-12-len(bodyHead), "pcapng block body")
		if err != nil {
			return Packet{}, unexpected(err)
		}
		if len(bodyHead) > 0 {
			body = append(append([]byte(nil), bodyHead...), body...)
		}
		trailer, err := r.read(4, "pcapng block trailer")
		if err != nil {
			return Packet{}, unexpected(err)
		}
		// The duplicated length is the format's own corruption check; honouring
		// it is what lets a reader trust that it skipped an unknown block by
		// exactly the right amount.
		if got := int(bo.Uint32(trailer)); got != total {
			return Packet{}, fmt.Errorf("pcapng: block 0x%X trailer length %d does not match header length %d", raw, got, total)
		}

		btype := blockSectionHeader
		if !isSHB {
			btype = int(bo.Uint32(raw))
		}
		switch btype {
		case blockSectionHeader:
			if err := r.ng.readSHB(bo, body); err != nil {
				return Packet{}, err
			}
		case blockInterfaceDesc:
			if err := r.ng.readIDB(body); err != nil {
				return Packet{}, err
			}
		case blockEnhancedPacket:
			return r.ng.readEPB(body)
		case blockSimplePacket:
			return r.ng.readSPB(body)
		default:
			// NRB / ISB / DSB / custom / anything a future revision adds.
			continue
		}
	}
}

// unexpected upgrades a clean EOF inside a block to ErrUnexpectedEOF: a file
// that stops between a block's header and its trailer is truncated, not done.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("pcapng: capture ends inside a block: %w", io.ErrUnexpectedEOF)
	}
	return err
}

func (s *ngState) readSHB(bo binary.ByteOrder, body []byte) error {
	// byte-order magic(4) major(2) minor(2) section length(8) options...
	if len(body) < 16 {
		return fmt.Errorf("pcapng: Section Header Block body is %d bytes, want at least 16", len(body))
	}
	s.bo = bo
	s.major = bo.Uint16(body[4:6])
	s.minor = bo.Uint16(body[6:8])
	if s.major != 1 {
		return fmt.Errorf("pcapng: unsupported format version %d.%d", s.major, s.minor)
	}
	// A new section restarts interface numbering from zero. Carrying the old
	// list over would silently dissect packets with the wrong link type.
	s.interfaces = nil
	return nil
}

func (s *ngState) readIDB(body []byte) error {
	// linktype(2) reserved(2) snaplen(4) options...
	if len(body) < 8 {
		return fmt.Errorf("pcapng: Interface Description Block body is %d bytes, want at least 8", len(body))
	}
	iface := ngInterface{
		LinkType:  s.bo.Uint16(body[0:2]),
		SnapLen:   s.bo.Uint32(body[4:8]),
		PerSecond: 1e6, // if_tsresol default: microseconds
	}
	opts, err := parseOptions(s.bo, body[8:])
	if err != nil {
		return fmt.Errorf("pcapng: Interface Description Block options: %w", err)
	}
	for _, o := range opts {
		switch o.code {
		case optIfTsResol:
			if len(o.value) != 1 {
				return fmt.Errorf("pcapng: if_tsresol option is %d bytes, want 1", len(o.value))
			}
			per, err := tsResolution(o.value[0])
			if err != nil {
				return err
			}
			iface.PerSecond = per
		case optIfName:
			iface.Name = string(o.value)
		}
	}
	if len(s.interfaces) >= 1<<16 {
		return errors.New("pcapng: absurd number of Interface Description Blocks")
	}
	s.interfaces = append(s.interfaces, iface)
	return nil
}

// tsResolution decodes if_tsresol: the low 7 bits are an exponent, and the top
// bit selects base 2 instead of base 10.
func tsResolution(v byte) (uint64, error) {
	exp := v & 0x7F
	if v&0x80 != 0 {
		if exp > 63 {
			return 0, fmt.Errorf("pcapng: if_tsresol 2^-%d is out of range", exp)
		}
		return uint64(1) << exp, nil
	}
	if exp > 19 {
		return 0, fmt.Errorf("pcapng: if_tsresol 10^-%d is out of range", exp)
	}
	per := uint64(1)
	for i := byte(0); i < exp; i++ {
		per *= 10
	}
	return per, nil
}

func (s *ngState) readEPB(body []byte) (Packet, error) {
	// interface id(4) ts high(4) ts low(4) captured len(4) original len(4) data...
	if len(body) < 20 {
		return Packet{}, fmt.Errorf("pcapng: Enhanced Packet Block body is %d bytes, want at least 20", len(body))
	}
	ifaceID := int(s.bo.Uint32(body[0:4]))
	if ifaceID >= len(s.interfaces) {
		return Packet{}, fmt.Errorf("pcapng: Enhanced Packet Block names interface %d but only %d are described", ifaceID, len(s.interfaces))
	}
	iface := s.interfaces[ifaceID]
	ticks := uint64(s.bo.Uint32(body[4:8]))<<32 | uint64(s.bo.Uint32(body[8:12]))
	capLen := int(s.bo.Uint32(body[12:16]))
	origLen := int(s.bo.Uint32(body[16:20]))
	if capLen < 0 || capLen > MaxPacketLen {
		return Packet{}, fmt.Errorf("pcapng: Enhanced Packet Block captured length %d exceeds the %d-byte limit", capLen, MaxPacketLen)
	}
	if 20+capLen > len(body) {
		return Packet{}, fmt.Errorf("pcapng: Enhanced Packet Block claims %d captured bytes but the block holds %d", capLen, len(body)-20)
	}
	if origLen < capLen {
		// Not fatal to parsing, but it means the writer disagrees with itself;
		// trusting origLen would understate the frame.
		origLen = capLen
	}
	ts, err := timestampFrom(ticks, iface.PerSecond)
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		Time:      ts,
		LinkType:  iface.LinkType,
		Interface: ifaceID,
		OrigLen:   origLen,
		Data:      append([]byte(nil), body[20:20+capLen]...),
	}, nil
}

func (s *ngState) readSPB(body []byte) (Packet, error) {
	// original len(4) data... — no interface id (implicitly 0), no timestamp.
	if len(body) < 4 {
		return Packet{}, fmt.Errorf("pcapng: Simple Packet Block body is %d bytes, want at least 4", len(body))
	}
	if len(s.interfaces) == 0 {
		return Packet{}, errors.New("pcapng: Simple Packet Block before any Interface Description Block")
	}
	iface := s.interfaces[0]
	origLen := int(s.bo.Uint32(body[0:4]))
	if origLen < 0 || origLen > MaxPacketLen {
		return Packet{}, fmt.Errorf("pcapng: Simple Packet Block original length %d exceeds the %d-byte limit", origLen, MaxPacketLen)
	}
	// An SPB carries no captured length: it is min(original, snaplen), and the
	// block must be big enough to hold it.
	capLen := origLen
	if iface.SnapLen > 0 && capLen > int(iface.SnapLen) {
		capLen = int(iface.SnapLen)
	}
	if 4+capLen > len(body) {
		return Packet{}, fmt.Errorf("pcapng: Simple Packet Block implies %d captured bytes but the block holds %d", capLen, len(body)-4)
	}
	return Packet{
		Time:      time.Time{}, // SPBs are timestamp-free by design
		LinkType:  iface.LinkType,
		Interface: 0,
		OrigLen:   origLen,
		Data:      append([]byte(nil), body[4:4+capLen]...),
	}, nil
}

type ngOption struct {
	code  uint16
	value []byte
}

// parseOptions walks a pcapng option list. A list that simply runs out (no
// opt_endofopt) is accepted — several writers omit the terminator — but a
// length that overruns the block is not.
func parseOptions(bo binary.ByteOrder, b []byte) ([]ngOption, error) {
	var out []ngOption
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("option list has a %d-byte tail, want a 4-byte option header", len(b))
		}
		code := bo.Uint16(b[0:2])
		length := int(bo.Uint16(b[2:4]))
		if code == optEndOfOpt && length == 0 {
			return out, nil
		}
		padded := align4(length)
		if 4+padded > len(b) {
			return nil, fmt.Errorf("option %d declares %d bytes but only %d remain", code, length, len(b)-4)
		}
		out = append(out, ngOption{code: code, value: b[4 : 4+length]})
		b = b[4+padded:]
	}
	return out, nil
}
