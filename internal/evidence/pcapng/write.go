package pcapng

// write.go writes classic libpcap files.
//
// Reading is this package's job, and writing is here for one reason: several
// governing specifications require a submission to carry PER-TEST captures with
// exact filenames — SS-CSIP-RESULTS-v1.1 Chapter 5 for COMM-004's certificate
// scenarios, and the Secure SunSpec Modbus CTP's Reporting Requirements for
// every one of its ~37 rows. Those files are slices of the run's single
// capture, so somebody has to write pcap, and a second implementation of the
// format alongside the reader would be a second thing to get wrong.
//
// Classic libpcap, not pcapng. Both are conformant; libpcap is one 24-byte file
// header and one 16-byte record header per frame, a format whose correctness is
// inspectable at a glance, and ReadFile round-trips it — which is what lets an
// exporter re-read what it wrote and report the FILE's contents rather than the
// intent behind it.

import (
	"encoding/binary"
	"fmt"
	"io"
)

// magicMicro is the classic little-endian microsecond magic — what `tcpdump -w`
// writes and what this package's reader accepts.
const magicMicro = 0xA1B2C3D4

// SnapLen is the maximum captured length across pkts, for the file header.
//
// It is the maximum PRESENT, not a truncation the writer applies: nothing here
// ever shortens a frame, because a trace whose handshake was clipped is worse
// than no trace.
func SnapLen(pkts []Packet) uint32 {
	max := uint32(0)
	for _, p := range pkts {
		if n := uint32(len(p.Data)); n > max {
			max = n
		}
	}
	if max == 0 {
		return 65535
	}
	return max
}

// WriteLegacy writes packets as a classic libpcap file.
//
// Every frame is written whole, with its original wire length preserved in the
// record header, so a reader can still tell that a frame was truncated by the
// CAPTURE — a fact that must survive into the exported slice, since a truncated
// handshake record cannot prove what a complete one would.
//
// Mixed link types are refused rather than coerced: one libpcap file declares
// exactly one link type in its header, and writing Ethernet frames under a
// Linux-cooked declaration would produce a file that parses and lies.
func WriteLegacy(w io.Writer, linkType uint16, pkts []Packet) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], magicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], SnapLen(pkts))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("pcapng: write pcap header: %w", err)
	}
	rec := make([]byte, 16)
	for _, p := range pkts {
		if p.LinkType != linkType {
			return fmt.Errorf("pcapng: frame %d has link type %d but the trace declares %d; "+
				"a single libpcap file cannot mix link types", p.Index, p.LinkType, linkType)
		}
		binary.LittleEndian.PutUint32(rec[0:4], uint32(p.Time.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(p.Time.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p.Data)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(p.OrigLen))
		if _, err := w.Write(rec); err != nil {
			return fmt.Errorf("pcapng: write pcap record header: %w", err)
		}
		if _, err := w.Write(p.Data); err != nil {
			return fmt.Errorf("pcapng: write pcap frame %d: %w", p.Index, err)
		}
	}
	return nil
}
