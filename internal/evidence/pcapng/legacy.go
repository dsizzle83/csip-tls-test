package pcapng

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Classic libpcap file magics. The "swapped" spellings are the same constants
// written by a host of the opposite endianness — a capture taken on a big-endian
// device (some gateway SoCs, some managed switches' port-mirror exports) and
// analysed on the desktop hits these paths, which is why both are supported
// rather than assuming the file was written here.
const (
	pcapMagicMicro        = 0xA1B2C3D4 // seconds + microseconds
	pcapMagicMicroSwapped = 0xD4C3B2A1
	pcapMagicNano         = 0xA1B23C4D // seconds + nanoseconds (tcpdump -j / libpcap 1.5+)
	pcapMagicNanoSwapped  = 0x4D3CB2A1
)

// pcapFileHeaderLen / pcapRecordHeaderLen are fixed by the format.
const (
	pcapFileHeaderLen   = 24
	pcapRecordHeaderLen = 16
)

// pcState is the immutable header of a classic capture plus the byte order and
// timestamp scale it implies.
type pcState struct {
	bo        binary.ByteOrder
	nano      bool
	snapLen   uint32
	linkType  uint16
	major     uint16
	minor     uint16
	fcsExtras uint32 // top bits of the network field: FCS length hints, informational
}

// readPcapHeader consumes the 24-byte global header and validates it.
func readPcapHeader(br *bufio.Reader) (*pcState, error) {
	hdr := make([]byte, pcapFileHeaderLen)
	if n, err := io.ReadFull(br, hdr); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("pcapng: file is %d bytes, too short for a %d-byte libpcap header: %w",
				n, pcapFileHeaderLen, ErrNotCapture)
		}
		return nil, fmt.Errorf("pcapng: read libpcap header: %w", err)
	}

	st := &pcState{}
	be := binary.BigEndian.Uint32(hdr[0:4])
	switch be {
	case pcapMagicMicro:
		st.bo, st.nano = binary.BigEndian, false
	case pcapMagicMicroSwapped:
		st.bo, st.nano = binary.LittleEndian, false
	case pcapMagicNano:
		st.bo, st.nano = binary.BigEndian, true
	case pcapMagicNanoSwapped:
		st.bo, st.nano = binary.LittleEndian, true
	default:
		return nil, fmt.Errorf("pcapng: leading magic 0x%08X is not a known libpcap magic: %w", be, ErrNotCapture)
	}

	st.major = st.bo.Uint16(hdr[4:6])
	st.minor = st.bo.Uint16(hdr[6:8])
	if st.major != 2 {
		return nil, fmt.Errorf("pcapng: unsupported libpcap version %d.%d", st.major, st.minor)
	}
	// hdr[8:12] thiszone and hdr[12:16] sigfigs are ignored: libpcap has never
	// written anything but zero in either, and honouring a non-zero thiszone
	// would shift every timestamp away from the UTC the rest of the bundle uses.
	st.snapLen = st.bo.Uint32(hdr[16:20])
	network := st.bo.Uint32(hdr[20:24])
	// The upper 16 bits of "network" carry an optional FCS-length hint
	// (LINKTYPE_ ... | (fcslen << 28) | 0x10000000). The link type proper is the
	// low 16 bits.
	st.linkType = uint16(network & 0xFFFF)
	st.fcsExtras = network >> 16
	return st, nil
}

// nextPcap reads one record: a 16-byte header then incl_len bytes of frame.
func (r *Reader) nextPcap() (Packet, error) {
	hdr, err := r.read(pcapRecordHeaderLen, "libpcap record header")
	if err != nil {
		return Packet{}, err // io.EOF here is the clean end of the file
	}
	st := r.pc
	tsSec := uint64(st.bo.Uint32(hdr[0:4]))
	tsFrac := uint64(st.bo.Uint32(hdr[4:8]))
	inclLen := int(st.bo.Uint32(hdr[8:12]))
	origLen := int(st.bo.Uint32(hdr[12:16]))

	if inclLen < 0 || inclLen > MaxPacketLen {
		return Packet{}, fmt.Errorf("pcapng: libpcap record declares %d captured bytes, over the %d-byte limit", inclLen, MaxPacketLen)
	}
	// A record longer than the file's own snaplen means the header and the
	// records disagree; that is corruption, and reading inclLen bytes anyway
	// would resynchronise onto whatever follows.
	if st.snapLen > 0 && inclLen > int(st.snapLen) {
		return Packet{}, fmt.Errorf("pcapng: libpcap record declares %d captured bytes, over the file's snaplen %d", inclLen, st.snapLen)
	}
	if origLen < inclLen {
		origLen = inclLen
	}

	data, err := r.read(inclLen, "libpcap record data")
	if err != nil {
		if errors.Is(err, io.EOF) {
			return Packet{}, fmt.Errorf("pcapng: libpcap record header promises %d bytes that the file does not contain: %w",
				inclLen, io.ErrUnexpectedEOF)
		}
		return Packet{}, err
	}

	perSecond := uint64(1e6)
	if st.nano {
		perSecond = 1e9
	}
	if tsFrac >= perSecond {
		return Packet{}, fmt.Errorf("pcapng: libpcap record timestamp fraction %d is not below %d", tsFrac, perSecond)
	}
	ts := time.Unix(int64(tsSec), int64(tsFrac*(1e9/perSecond))).UTC()

	return Packet{
		Time:      ts,
		LinkType:  st.linkType,
		Interface: 0,
		OrigLen:   origLen,
		Data:      data,
	}, nil
}
