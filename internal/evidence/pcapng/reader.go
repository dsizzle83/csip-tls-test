package pcapng

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"time"
)

// Format names the on-disk container a Reader detected.
type Format string

const (
	// FormatPcapng is the block-structured pcapng format (what dumpcap writes).
	FormatPcapng Format = "pcapng"
	// FormatPcap is the classic libpcap format (what tcpdump -w writes).
	FormatPcap Format = "pcap"
)

// Packet is one captured frame, as delivered by Reader.Next.
//
// Index is 1-based and counts every packet the reader has yielded from this
// file, in file order. It is THE citation key for the whole evidence engine:
// an assertion that says "the fatal alert is frame 4471" means Packet.Index
// 4471 of the bundle's capture, and Wireshark's frame.number column agrees
// with it (Wireshark also counts from 1, over the same block sequence).
//
// Data is a private copy owned by the caller — the reader never hands out a
// slice of a buffer it will reuse, because packets are routinely retained for
// the life of a run (a reassembler holds every segment of a stream).
type Packet struct {
	Index     int       // 1-based, matches Wireshark's frame.number
	Time      time.Time // UTC; zero for pcapng Simple Packet Blocks, which carry no timestamp
	LinkType  uint16    // LINKTYPE_* of the interface this packet arrived on
	Interface int       // pcapng interface id; always 0 for classic pcap
	OrigLen   int       // length on the wire before snaplen truncation
	Data      []byte    // captured bytes (len(Data) <= OrigLen)
}

// Truncated reports whether the capture kept fewer bytes than were on the wire.
// A truncated frame can still prove a header-level claim but must never be used
// to prove a payload-level one, so callers that cite byte ranges check this.
func (p Packet) Truncated() bool { return len(p.Data) < p.OrigLen }

// Size limits. Both are far above anything a real capture produces (a jumbo
// frame is 9 KiB; the largest pcapng block dumpcap writes is a Name Resolution
// Block of a few KiB) and exist purely so a corrupt or hostile length field
// cannot turn into a multi-gigabyte allocation.
const (
	// MaxBlockLen bounds a single pcapng block, header and trailer included.
	MaxBlockLen = 64 << 20
	// MaxPacketLen bounds one packet's captured bytes.
	MaxPacketLen = 16 << 20
)

// ErrNotCapture is returned when the first bytes match neither a pcapng Section
// Header Block nor any classic libpcap magic.
var ErrNotCapture = errors.New("pcapng: not a pcapng or libpcap capture file")

// Reader yields packets from a capture file. It is a forward-only streaming
// reader: it never seeks, so it works on a pipe, and it holds at most one
// block in memory at a time.
//
// A Reader is not safe for concurrent use.
type Reader struct {
	src    *bufio.Reader
	closer io.Closer
	format Format
	index  int

	ng *ngState // set when format == FormatPcapng
	pc *pcState // set when format == FormatPcap

	sticky error // first hard error; latched so Next stays terminal
}

// NewReader detects the capture format from the leading bytes of r and returns
// a Reader positioned at the first packet. The file header is validated eagerly
// so that "this is not a capture" is reported at open time rather than as a
// mysterious failure on the first Next.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic, err := br.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("pcapng: file is too short to be a capture (%d bytes): %w", len(magic), ErrNotCapture)
		}
		return nil, fmt.Errorf("pcapng: read file magic: %w", err)
	}

	rd := &Reader{src: br}
	switch {
	case magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A:
		// Section Header Block. The block type is a palindrome precisely so it
		// reads the same in either endianness; the byte-order magic inside the
		// block is what actually settles it.
		rd.format = FormatPcapng
		rd.ng = &ngState{}
	default:
		st, err := readPcapHeader(br)
		if err != nil {
			return nil, err
		}
		rd.format = FormatPcap
		rd.pc = st
	}
	return rd, nil
}

// Open opens a capture file by path. Close it when done.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pcapng: open capture: %w", err)
	}
	rd, err := NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("pcapng: %s: %w", path, err)
	}
	rd.closer = f
	return rd, nil
}

// Close releases the underlying file, if the Reader owns one.
func (r *Reader) Close() error {
	if r.closer == nil {
		return nil
	}
	err := r.closer.Close()
	r.closer = nil
	return err
}

// Format reports which container the Reader detected.
func (r *Reader) Format() Format { return r.format }

// Next returns the next packet, or io.EOF at a clean end of file. Any other
// error means the file is malformed or truncated from that point on; the error
// is latched, so a caller that keeps calling Next gets the same error rather
// than resynchronising onto garbage.
func (r *Reader) Next() (Packet, error) {
	if r.sticky != nil {
		return Packet{}, r.sticky
	}
	var (
		p   Packet
		err error
	)
	if r.format == FormatPcapng {
		p, err = r.nextNG()
	} else {
		p, err = r.nextPcap()
	}
	if err != nil {
		r.sticky = err
		return Packet{}, err
	}
	r.index++
	p.Index = r.index
	return p, nil
}

// ReadAll drains the Reader. It returns the packets read before any error, so a
// caller can still work with the frames of a capture whose tail was truncated —
// with the error in hand to say so.
func ReadAll(r *Reader) ([]Packet, error) {
	var out []Packet
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}

// ReadFile opens path and reads every packet. Like ReadAll it returns the
// packets that were readable alongside any tail error.
func ReadFile(path string) ([]Packet, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return ReadAll(r)
}

// read returns exactly n bytes. A clean EOF at a block boundary (nothing read)
// surfaces as io.EOF; anything else is io.ErrUnexpectedEOF with the context of
// what was being read, because "the file ends in the middle of an EPB header"
// is a materially different fact from "the file ends".
func (r *Reader) read(n int, what string) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	if n < 0 || n > MaxBlockLen {
		return nil, fmt.Errorf("pcapng: refusing %d-byte read for %s (limit %d)", n, what, MaxBlockLen)
	}
	buf := make([]byte, n)
	got, err := io.ReadFull(r.src, buf)
	switch {
	case err == nil:
		return buf, nil
	case errors.Is(err, io.EOF) && got == 0:
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("pcapng: truncated %s: have %d of %d bytes: %w", what, got, n, io.ErrUnexpectedEOF)
	}
}

// align4 rounds up to the 32-bit boundary pcapng pads every variable-length
// field to.
func align4(n int) int { return (n + 3) &^ 3 }

// timestampFrom converts a pcapng 64-bit tick count into a wall-clock time
// given the interface's ticks-per-second. The multiply is done in 128 bits
// because a nanosecond-resolution capture already needs 60 bits for the whole
// count and if_tsresol permits resolutions far finer than that; doing it in
// float64 would quietly lose the low bits of the fractional second, which is
// exactly the part an evidence timeline cares about when two frames are 40 µs
// apart.
func timestampFrom(ticks, perSecond uint64) (time.Time, error) {
	if perSecond == 0 {
		return time.Time{}, errors.New("pcapng: interface declares zero timestamp resolution")
	}
	sec := ticks / perSecond
	frac := ticks % perSecond
	hi, lo := bits.Mul64(frac, 1e9)
	nsec, _ := bits.Div64(hi, lo, perSecond) // safe: frac < perSecond ⇒ hi < perSecond
	if sec > 1<<40 {
		return time.Time{}, fmt.Errorf("pcapng: timestamp %d ticks at %d/s is out of range", ticks, perSecond)
	}
	return time.Unix(int64(sec), int64(nsec)).UTC(), nil
}
