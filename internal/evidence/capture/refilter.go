package capture

// refilter.go re-applies the requested capture filter to the frames the tool
// actually wrote, and replaces the capture file with the frames that survive.
//
// # Why this exists
//
// See filter.go: dumpcap's per-interface kernel filter can go unarmed on the
// first-listed interface for a whole capture, and nothing it prints says so.
// The consequence is not a flaky test, it is a hygiene failure — an evidence
// bundle handed to a laboratory containing thousands of frames of somebody's
// mDNS, DNS-SD and HTTP, from a run that asked for `tcp port 802`. Redaction is
// the entire reason the capture is filtered and the interface is not put in
// promiscuous mode; a filter that silently did not run defeats both.
//
// # Why the FILTERED file is the artefact, and the raw one is not kept
//
// The bundle ships one capture and every citation in it is a frame NUMBER into
// that capture (pcapng.Packet.Index, which is Wireshark's frame.number). Two
// files would mean two numbering schemes for one run. Keeping the raw file
// beside the filtered one would also keep the traffic the filter exists to
// exclude — in the same directory, covered by the same manifest, handed to the
// same reviewer. So the raw frames go, and what stays is the COUNT of what
// went, per interface, in the capture summary and in the report: nothing is
// hidden, and the thing that could not be handed over is not handed over.
//
// # Where it runs, and why there
//
// Inside Stop, before Stop reports the file's contents, which is before
// anything else in the engine has read the capture: the runner loads its frame
// index (internal/certify: LoadFrameIndex) after Stop returns, and every
// citation, every per-case pcap slice and every digest is derived from that
// load. Filtering here therefore leaves every frame number in the bundle
// pointing into the file the bundle ships, with no reordering needed anywhere
// downstream — and Summary.Packets, which bundle.Verify re-checks against the
// shipped pcap, counts the frames that are actually in it.
//
// # How the file is rewritten
//
// By copying blocks, not by re-encoding packets. Every block that is not a
// packet — the Section Header, every Interface Description Block with its
// name/link type/timestamp resolution, Name Resolution, Interface Statistics,
// Decryption Secrets, anything a future pcapng revision adds — is written
// through byte for byte, and packet blocks are written through byte for byte
// or not at all. Nothing is re-timestamped, re-scaled or re-endianed, so a
// filtered capture is a strict subsequence of the tool's own output rather than
// this package's rendering of it. When no frame is dropped the file is not
// touched at all, so an ordinary run on a healthy bench still ships the exact
// bytes dumpcap wrote.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"csip-tls-test/internal/evidence/pcapng"
)

// pcapng block types this file has to recognise. Only the two that carry
// frames matter; everything else is copied through unread, which is what the
// format's length-prefixed block structure is for.
const (
	ngBlockSectionHeader  = 0x0A0D0D0A
	ngBlockSimplePacket   = 0x00000003
	ngBlockEnhancedPacket = 0x00000006
)

// ngByteOrderMagic is the Section Header Block field that settles endianness.
const ngByteOrderMagic = 0x1A2B3C4D

// Classic libpcap magics, in the order the 24-byte header presents them.
const (
	pcapMagicMicro        = 0xA1B2C3D4
	pcapMagicMicroSwapped = 0xD4C3B2A1
	pcapMagicNano         = 0xA1B23C4D
	pcapMagicNanoSwapped  = 0x4D3CB2A1
)

const (
	pcapFileHeaderLen   = 24
	pcapRecordHeaderLen = 16
)

// InterfaceFrames is one capture interface's frame accounting.
//
// It exists because "the capture holds 4471 frames" is not enough to notice
// that 2446 of them came off the wrong NIC unfiltered. A multi-interface
// capture is one file, one frame numbering and one packet count; the split by
// interface, and what the post-capture re-filter had to do to each side of it,
// is the only place the tool race is visible.
type InterfaceFrames struct {
	// ID is the pcapng interface id frames carry, which is the position of the
	// -i flag that created it. Always 0 for a classic libpcap capture.
	ID int `json:"id"`
	// Name is the interface named at that position, when it is known.
	Name string `json:"name,omitempty"`
	// Captured is how many frames the capture tool wrote for this interface.
	Captured int `json:"captured"`
	// Kept is how many of them are in the file the bundle ships.
	Kept int `json:"kept"`
	// Dropped is how many the post-capture re-filter removed because they
	// provably did not match the requested filter. Any value above zero means
	// the tool's kernel filter was not doing its job on this interface.
	Dropped int `json:"dropped,omitempty"`
	// Undecided counts frames KEPT although the re-filter could not decide
	// them — a header the dissector rejects, a first IP fragment, an SCTP
	// association (see filter.go). They are disclosed rather than dropped: the
	// hygiene pass may add redaction, never destroy evidence.
	Undecided int `json:"undecided,omitempty"`
	// FilterUnarmedSuspected is Dropped > 0, named for what it means. The
	// capture tool was given a filter and this interface still delivered
	// frames that do not match it, which is the observable form of "the kernel
	// filter was never armed here".
	FilterUnarmedSuspected bool `json:"filter_unarmed_suspected,omitempty"`
}

// refilterResult is what one hygiene pass did.
type refilterResult struct {
	interfaces []InterfaceFrames
	kept       []bool // per frame, in file order
	dropped    int
	undecided  int
}

// classify decides every captured frame and tallies the result per interface.
//
// A nil filter means no filter was requested: every frame is kept, and the
// per-interface counts are still produced, because the split between taps is
// worth recording whether or not anything had to be removed.
func classify(f *Filter, pkts []pcapng.Packet, ifaces []string) refilterResult {
	res := refilterResult{kept: make([]bool, len(pkts))}
	byID := make(map[int]*InterfaceFrames, len(ifaces))
	// Every interface that was ASKED for gets a row, even one that delivered
	// nothing. On a split bench "enp1s0 captured 0 frames" is the shape of a
	// mis-cabled or down NIC, and it is invisible if the row only appears once
	// a frame arrives on it.
	for id, name := range ifaces {
		byID[id] = &InterfaceFrames{ID: id, Name: name}
	}
	for i, p := range pkts {
		st, ok := byID[p.Interface]
		if !ok {
			st = &InterfaceFrames{ID: p.Interface, Name: interfaceName(ifaces, p.Interface)}
			byID[p.Interface] = st
		}
		st.Captured++

		m := matchYes
		if f != nil {
			m = f.eval(p)
		}
		switch m {
		case matchNo:
			st.Dropped++
			st.FilterUnarmedSuspected = true
			res.dropped++
		case matchUnknown:
			st.Undecided++
			st.Kept++
			res.undecided++
			res.kept[i] = true
		default:
			st.Kept++
			res.kept[i] = true
		}
	}
	res.interfaces = make([]InterfaceFrames, 0, len(byID))
	for _, st := range byID {
		res.interfaces = append(res.interfaces, *st)
	}
	sort.Slice(res.interfaces, func(i, j int) bool { return res.interfaces[i].ID < res.interfaces[j].ID })
	return res
}

// interfaceName maps a pcapng interface id back to the -i argument that
// created it. dumpcap emits one Interface Description Block per -i, in order,
// so the id is that position. An id with no name (a capture whose file has more
// interfaces than the command line had flags, which should not happen) is
// reported by number alone rather than guessed at.
//
// pcapng permits several SECTIONS in one file, each with its own interface
// list, so an id is only unique within a section; a two-section file would have
// its two id-0 interfaces tallied together here. dumpcap writes one section per
// file and the reader has never seen otherwise, and conflating is the safe
// direction anyway: it can understate which tap leaked, never invent one.
func interfaceName(ifaces []string, id int) string {
	if id < 0 || id >= len(ifaces) {
		return ""
	}
	return ifaces[id]
}

// rewriteFiltered replaces the capture at path with one holding only the frames
// keep marks, leaving every other block byte for byte as the tool wrote it.
//
// The new file is built beside the old one and renamed over it, so a failure
// anywhere leaves the original capture intact: a half-written evidence file is
// worse than an unfiltered one, because the unfiltered one at least parses.
func rewriteFiltered(path string, keep []bool) (err error) {
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("capture: re-open capture for filtering: %w", err)
	}
	defer func() { _ = src.Close() }()

	fi, err := src.Stat()
	if err != nil {
		return fmt.Errorf("capture: stat capture for filtering: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".refilter-*")
	if err != nil {
		return fmt.Errorf("capture: create filtered capture: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	w := bufio.NewWriterSize(tmp, 128<<10)
	if err = copyKept(bufio.NewReaderSize(src, 128<<10), w, keep); err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return fmt.Errorf("capture: write filtered capture: %w", err)
	}
	// The filtered file is the evidence artefact and the manifest will hash it;
	// it is worth the one fsync to know it is on the disk it will be read from.
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("capture: flush filtered capture: %w", err)
	}
	if err = tmp.Chmod(fi.Mode().Perm()); err != nil {
		return fmt.Errorf("capture: set filtered capture mode: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("capture: close filtered capture: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("capture: replace capture with its filtered form: %w", err)
	}
	return nil
}

// copyKept streams one capture file to another, dropping the packet records
// whose keep entry is false and copying every other byte unchanged.
func copyKept(r *bufio.Reader, w io.Writer, keep []bool) error {
	magic, err := r.Peek(4)
	if err != nil {
		return fmt.Errorf("capture: read capture magic for filtering: %w", err)
	}
	if magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		return copyKeptPcapng(r, w, keep)
	}
	return copyKeptPcap(r, w, keep)
}

// copyKeptPcapng walks blocks. Only the block type and the two length fields
// are ever interpreted; the body is opaque.
func copyKeptPcapng(r *bufio.Reader, w io.Writer, keep []bool) error {
	var bo binary.ByteOrder
	seen := 0
	for {
		head, err := readOrEOF(r, 4)
		if err != nil {
			return err
		}
		if head == nil {
			break // clean end of file at a block boundary
		}
		isSHB := head[0] == 0x0A && head[1] == 0x0D && head[2] == 0x0D && head[3] == 0x0A

		lenRaw, err := readExactly(r, 4, "pcapng block length")
		if err != nil {
			return err
		}
		var magic []byte
		if isSHB {
			if magic, err = readExactly(r, 4, "pcapng byte-order magic"); err != nil {
				return err
			}
			switch {
			case binary.LittleEndian.Uint32(magic) == ngByteOrderMagic:
				bo = binary.LittleEndian
			case binary.BigEndian.Uint32(magic) == ngByteOrderMagic:
				bo = binary.BigEndian
			default:
				return fmt.Errorf("capture: filtering capture: bad byte-order magic 0x%X in Section Header Block", magic)
			}
		}
		if bo == nil {
			return fmt.Errorf("capture: filtering capture: first block is type 0x%X, want a Section Header Block", head)
		}

		total := int(bo.Uint32(lenRaw))
		// 12 = type(4) + length(4) + trailing length(4), and the format pads
		// every block to a 32-bit boundary. A length that leaves no room for
		// the bytes already read is corruption, not a short block.
		bodyLen := total - 12 - len(magic)
		if total < 12 || total%4 != 0 || total > pcapng.MaxBlockLen || bodyLen < 0 {
			return fmt.Errorf("capture: filtering capture: block 0x%X declares an unusable length %d", head, total)
		}
		body, err := readExactly(r, bodyLen, "pcapng block body")
		if err != nil {
			return err
		}
		trailer, err := readExactly(r, 4, "pcapng block trailer")
		if err != nil {
			return err
		}
		if got := int(bo.Uint32(trailer)); got != total {
			return fmt.Errorf("capture: filtering capture: block 0x%X trailer length %d does not match header length %d",
				head, got, total)
		}

		btype := ngBlockSectionHeader
		if !isSHB {
			btype = int(bo.Uint32(head))
		}
		if btype == ngBlockEnhancedPacket || btype == ngBlockSimplePacket {
			seen++
			if seen > len(keep) {
				return fmt.Errorf("capture: filtering capture: file holds more packet blocks than the %d frames read from it", len(keep))
			}
			if !keep[seen-1] {
				continue
			}
		}
		for _, chunk := range [][]byte{head, lenRaw, magic, body, trailer} {
			if len(chunk) == 0 {
				continue
			}
			if _, err := w.Write(chunk); err != nil {
				return fmt.Errorf("capture: write filtered capture: %w", err)
			}
		}
	}
	if seen != len(keep) {
		return fmt.Errorf("capture: filtering capture: file holds %d packet blocks but %d frames were read from it",
			seen, len(keep))
	}
	return nil
}

// copyKeptPcap walks classic libpcap records: a 24-byte file header, then a
// 16-byte record header and its frame, repeated.
func copyKeptPcap(r *bufio.Reader, w io.Writer, keep []bool) error {
	hdr, err := readExactly(r, pcapFileHeaderLen, "libpcap file header")
	if err != nil {
		return err
	}
	var bo binary.ByteOrder
	switch binary.BigEndian.Uint32(hdr[0:4]) {
	case pcapMagicMicro, pcapMagicNano:
		bo = binary.BigEndian
	case pcapMagicMicroSwapped, pcapMagicNanoSwapped:
		bo = binary.LittleEndian
	default:
		return fmt.Errorf("capture: filtering capture: leading magic 0x%08X is not a known libpcap magic",
			binary.BigEndian.Uint32(hdr[0:4]))
	}
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("capture: write filtered capture: %w", err)
	}

	seen := 0
	for {
		rec, err := readOrEOF(r, pcapRecordHeaderLen)
		if err != nil {
			return err
		}
		if rec == nil {
			break
		}
		inclLen := int(bo.Uint32(rec[8:12]))
		if inclLen < 0 || inclLen > pcapng.MaxPacketLen {
			return fmt.Errorf("capture: filtering capture: libpcap record declares %d captured bytes", inclLen)
		}
		data, err := readExactly(r, inclLen, "libpcap record data")
		if err != nil {
			return err
		}
		seen++
		if seen > len(keep) {
			return fmt.Errorf("capture: filtering capture: file holds more records than the %d frames read from it", len(keep))
		}
		if !keep[seen-1] {
			continue
		}
		if _, err := w.Write(rec); err != nil {
			return fmt.Errorf("capture: write filtered capture: %w", err)
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("capture: write filtered capture: %w", err)
		}
	}
	if seen != len(keep) {
		return fmt.Errorf("capture: filtering capture: file holds %d records but %d frames were read from it",
			seen, len(keep))
	}
	return nil
}

// readOrEOF reads exactly n bytes, or returns (nil, nil) at a clean end of
// file. Anything in between is a truncated file and an error.
func readOrEOF(r *bufio.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := io.ReadFull(r, buf)
	switch {
	case err == nil:
		return buf, nil
	case errors.Is(err, io.EOF) && got == 0:
		return nil, nil
	default:
		return nil, fmt.Errorf("capture: filtering capture: file ends after %d of %d bytes: %w", got, n, io.ErrUnexpectedEOF)
	}
}

// readExactly reads exactly n bytes; a short read is always an error here,
// because the caller is inside a record whose length the file itself declared.
func readExactly(r *bufio.Reader, n int, what string) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("capture: filtering capture: refusing a %d-byte read for %s", n, what)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	got, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("capture: filtering capture: truncated %s: have %d of %d bytes: %w",
			what, got, n, io.ErrUnexpectedEOF)
	}
	return buf, nil
}
