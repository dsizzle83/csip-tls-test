package pcapng

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ngBuilder assembles pcapng files byte by byte so the tests own every field
// they assert on. Building fixtures with a library would only prove that the
// library round-trips itself; hand-laid bytes prove the reader agrees with the
// format specification.
type ngBuilder struct {
	bo  binary.ByteOrder
	buf []byte
}

func newNG(bo binary.ByteOrder) *ngBuilder { return &ngBuilder{bo: bo} }

func (b *ngBuilder) u16(v uint16) []byte {
	out := make([]byte, 2)
	b.bo.PutUint16(out, v)
	return out
}

func (b *ngBuilder) u32(v uint32) []byte {
	out := make([]byte, 4)
	b.bo.PutUint32(out, v)
	return out
}

// block frames a body with the type/length/…/length envelope, padding the body
// to a 32-bit boundary.
func (b *ngBuilder) block(btype uint32, body []byte) {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(12 + len(body))
	b.buf = append(b.buf, b.u32(btype)...)
	b.buf = append(b.buf, b.u32(total)...)
	b.buf = append(b.buf, body...)
	b.buf = append(b.buf, b.u32(total)...)
}

func (b *ngBuilder) shb() {
	body := append([]byte(nil), b.u32(byteOrderMagic)...)
	body = append(body, b.u16(1)...)                      // major
	body = append(body, b.u16(0)...)                      // minor
	body = append(body, bytes.Repeat([]byte{0xFF}, 8)...) // section length: unknown
	body = append(body, b.u16(optEndOfOpt)...)
	body = append(body, b.u16(0)...)
	b.block(blockSectionHeader, body)
}

// idb writes an Interface Description Block for "lo". tsresol < 0 omits the
// option, so the reader must fall back to the microsecond default.
func (b *ngBuilder) idb(linkType uint16, snaplen uint32, tsresol int) {
	b.idbNamed(linkType, snaplen, tsresol, "lo")
}

// idbNamed writes an Interface Description Block carrying an if_name. A pcapng
// may describe SEVERAL interfaces, each with its own link type and timestamp
// resolution, and every packet names the one it arrived on — which is what
// `dumpcap -i A -i B` produces for a split bench.
func (b *ngBuilder) idbNamed(linkType uint16, snaplen uint32, tsresol int, name string) {
	body := append([]byte(nil), b.u16(linkType)...)
	body = append(body, b.u16(0)...) // reserved
	body = append(body, b.u32(snaplen)...)
	if tsresol >= 0 {
		body = append(body, b.u16(optIfTsResol)...)
		body = append(body, b.u16(1)...)
		body = append(body, byte(tsresol), 0, 0, 0)
	}
	body = append(body, b.u16(optIfName)...)
	body = append(body, b.u16(uint16(len(name)))...)
	body = append(body, name...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, b.u16(optEndOfOpt)...)
	body = append(body, b.u16(0)...)
	b.block(blockInterfaceDesc, body)
}

func (b *ngBuilder) epb(iface uint32, ticks uint64, data []byte, origLen uint32) {
	body := append([]byte(nil), b.u32(iface)...)
	body = append(body, b.u32(uint32(ticks>>32))...)
	body = append(body, b.u32(uint32(ticks))...)
	body = append(body, b.u32(uint32(len(data)))...)
	body = append(body, b.u32(origLen)...)
	body = append(body, data...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, b.u16(optEndOfOpt)...)
	body = append(body, b.u16(0)...)
	b.block(blockEnhancedPacket, body)
}

func (b *ngBuilder) spb(origLen uint32, data []byte) {
	body := append([]byte(nil), b.u32(origLen)...)
	body = append(body, data...)
	b.block(blockSimplePacket, body)
}

// unknown writes a block type the reader has never heard of; it must be skipped
// by length without disturbing the packet sequence.
func (b *ngBuilder) unknown(btype uint32, n int) {
	b.block(btype, bytes.Repeat([]byte{0xAB}, n))
}

func (b *ngBuilder) bytes() []byte { return b.buf }

// canonicalNG builds the reference three-packet capture used by most tests.
func canonicalNG(bo binary.ByteOrder) []byte {
	b := newNG(bo)
	b.shb()
	b.idb(1 /* Ethernet */, 262144, 6 /* microseconds */)
	b.unknown(blockNameResolution, 12)
	b.epb(0, 1_700_000_000_000_000, []byte("first-packet"), 12)
	b.epb(0, 1_700_000_000_500_000, []byte("second"), 99) // snaplen-truncated frame
	b.unknown(blockInterfaceStats, 8)
	b.spb(5, []byte("third"))
	return b.bytes()
}

func readAllBytes(t *testing.T, raw []byte) ([]Packet, error) {
	t.Helper()
	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return ReadAll(r)
}

func TestPcapngBothEndiannesses(t *testing.T) {
	for _, tc := range []struct {
		name string
		bo   binary.ByteOrder
	}{
		{"little-endian", binary.LittleEndian},
		{"big-endian", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := canonicalNG(tc.bo)
			r, err := NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if r.Format() != FormatPcapng {
				t.Fatalf("Format = %q, want %q", r.Format(), FormatPcapng)
			}
			pkts, err := ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if len(pkts) != 3 {
				t.Fatalf("got %d packets, want 3", len(pkts))
			}

			// Indices are 1-based and consecutive: they are the citation keys
			// the whole bundle format hangs on.
			for i, p := range pkts {
				if p.Index != i+1 {
					t.Errorf("packet %d has Index %d, want %d", i, p.Index, i+1)
				}
				if p.LinkType != 1 {
					t.Errorf("packet %d LinkType = %d, want 1", p.Index, p.LinkType)
				}
			}
			if got := string(pkts[0].Data); got != "first-packet" {
				t.Errorf("packet 1 data = %q", got)
			}
			want := time.Unix(1_700_000_000, 0).UTC()
			if !pkts[0].Time.Equal(want) {
				t.Errorf("packet 1 time = %v, want %v", pkts[0].Time, want)
			}
			if got, want := pkts[1].Time, time.Unix(1_700_000_000, 500_000_000).UTC(); !got.Equal(want) {
				t.Errorf("packet 2 time = %v, want %v", got, want)
			}
			if !pkts[1].Truncated() || pkts[1].OrigLen != 99 {
				t.Errorf("packet 2 should be snaplen-truncated: len=%d origLen=%d", len(pkts[1].Data), pkts[1].OrigLen)
			}
			// The Simple Packet Block carries no timestamp; the reader must say
			// so with a zero time rather than inventing one.
			if got := string(pkts[2].Data); got != "third" {
				t.Errorf("packet 3 data = %q", got)
			}
			if !pkts[2].Time.IsZero() {
				t.Errorf("Simple Packet Block time = %v, want zero", pkts[2].Time)
			}
		})
	}
}

func TestPcapngTimestampResolution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tsresol int
		ticks   uint64
		want    time.Time
		wantErr string
	}{
		{name: "default microseconds", tsresol: -1, ticks: 1_000_000_000_000_001, want: time.Unix(1_000_000_000, 1000).UTC()},
		{name: "explicit microseconds", tsresol: 6, ticks: 1_000_000_000_000_001, want: time.Unix(1_000_000_000, 1000).UTC()},
		{name: "nanoseconds", tsresol: 9, ticks: 1_000_000_000_000_000_007, want: time.Unix(1_000_000_000, 7).UTC()},
		{name: "milliseconds", tsresol: 3, ticks: 1_700_000_000_123, want: time.Unix(1_700_000_000, 123_000_000).UTC()},
		{name: "binary 2^-32", tsresol: 0x80 | 32, ticks: 1<<32 + 1<<31, want: time.Unix(1, 500_000_000).UTC()},
		{name: "absurd decimal exponent", tsresol: 25, wantErr: "out of range"},
		{name: "absurd binary exponent", tsresol: 0x80 | 90, wantErr: "out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newNG(binary.LittleEndian)
			b.shb()
			b.idb(1, 0, tc.tsresol)
			b.epb(0, tc.ticks, []byte("x"), 1)
			pkts, err := readAllBytes(t, b.bytes())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if len(pkts) != 1 {
				t.Fatalf("got %d packets, want 1", len(pkts))
			}
			if !pkts[0].Time.Equal(tc.want) {
				t.Errorf("time = %v (%d ns), want %v (%d ns)",
					pkts[0].Time, pkts[0].Time.UnixNano(), tc.want, tc.want.UnixNano())
			}
		})
	}
}

// TestPcapngMultipleSections proves a second Section Header Block resets both
// the endianness and the interface table. A reader that carried the first
// section's interface list forward would dissect the second section's frames
// with the wrong link type — a silent, evidence-destroying error.
func TestPcapngMultipleSections(t *testing.T) {
	le := newNG(binary.LittleEndian)
	le.shb()
	le.idb(1 /* Ethernet */, 0, 6)
	le.epb(0, 1_000_000, []byte("ether"), 5)

	be := newNG(binary.BigEndian)
	be.shb()
	be.idb(113 /* Linux SLL */, 0, 6)
	be.epb(0, 2_000_000, []byte("sll"), 3)

	raw := append(le.bytes(), be.bytes()...)
	pkts, err := readAllBytes(t, raw)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2", len(pkts))
	}
	if pkts[0].LinkType != 1 || pkts[1].LinkType != 113 {
		t.Fatalf("link types = %d,%d, want 1,113", pkts[0].LinkType, pkts[1].LinkType)
	}
	if pkts[1].Index != 2 {
		t.Errorf("second section's packet has Index %d, want 2 (numbering is per file, not per section)", pkts[1].Index)
	}
}

// TestPcapngMultipleInterfaces is the split-bench capture in miniature: one
// section, one packet sequence, TWO Interface Description Blocks, with frames
// interleaved between them.
//
// A reader that latched onto the FIRST interface — a plausible shortcut, since
// every capture before the split bench had exactly one — would dissect the
// second NIC's frames under the first NIC's link type and scale their
// timestamps by the first NIC's resolution. Both failures are silent: the
// frames still parse, they are simply wrong. So the fixture makes the two
// interfaces disagree on both axes, and asserts each frame got its own.
func TestPcapngMultipleInterfaces(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := newNG(bo)
		b.shb()
		// 0: the northbound NIC — Ethernet, microsecond ticks.
		b.idbNamed(1 /* Ethernet */, 262144, 6, "wlp2s0")
		// 1: the southbound NIC — a different link type and nanosecond ticks.
		b.idbNamed(113 /* Linux SLL */, 262144, 9, "enp1s0")
		b.epb(0, 1_700_000_000_000_000, []byte("north-one"), 9)
		b.epb(1, 1_700_000_000_000_000_000, []byte("south-one"), 9)
		b.epb(0, 1_700_000_000_250_000, []byte("north-two"), 9)
		b.epb(1, 1_700_000_000_500_000_000, []byte("south-two"), 9)

		pkts, err := readAllBytes(t, b.bytes())
		if err != nil {
			t.Fatalf("%v: ReadAll: %v", bo, err)
		}
		if len(pkts) != 4 {
			t.Fatalf("%v: got %d packets, want 4", bo, len(pkts))
		}

		for i, want := range []struct {
			iface    int
			linkType uint16
			data     string
			ts       time.Time
		}{
			{0, 1, "north-one", time.Unix(1_700_000_000, 0).UTC()},
			{1, 113, "south-one", time.Unix(1_700_000_000, 0).UTC()},
			{0, 1, "north-two", time.Unix(1_700_000_000, 250_000_000).UTC()},
			{1, 113, "south-two", time.Unix(1_700_000_000, 500_000_000).UTC()},
		} {
			p := pkts[i]
			if p.Interface != want.iface {
				t.Errorf("%v: frame %d Interface = %d, want %d", bo, p.Index, p.Interface, want.iface)
			}
			if p.LinkType != want.linkType {
				t.Errorf("%v: frame %d LinkType = %d, want %d — the frame was dissected as the "+
					"WRONG interface's link type", bo, p.Index, p.LinkType, want.linkType)
			}
			if string(p.Data) != want.data {
				t.Errorf("%v: frame %d data = %q, want %q", bo, p.Index, p.Data, want.data)
			}
			// The resolutions differ by a thousand: reading the ticks of one
			// interface at the other's if_tsresol is off by 1000x, not subtly.
			if !p.Time.Equal(want.ts) {
				t.Errorf("%v: frame %d Time = %v, want %v — the timestamp was scaled by the "+
					"wrong interface's if_tsresol", bo, p.Index, p.Time, want.ts)
			}
			// Frame numbering stays ONE sequence over the file, whatever the
			// interface: it is the citation key the whole bundle rests on, and
			// Wireshark numbers the same way.
			if p.Index != i+1 {
				t.Errorf("%v: frame %d has Index %d, want %d", bo, i, p.Index, i+1)
			}
		}
	}
}

func TestPcapngMalformed(t *testing.T) {
	bo := binary.LittleEndian
	mutate := func(f func(b *ngBuilder)) []byte {
		b := newNG(bo)
		f(b)
		return b.bytes()
	}

	// Offset of the first IDB option's length field: the SHB, then the IDB's
	// 8-byte envelope head, its 8-byte fixed body, and the option's 2-byte code.
	shbLen := len(mutate(func(b *ngBuilder) { b.shb() }))
	optLenOff := shbLen + 8 + 8 + 2

	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{
			name:    "no section header block",
			raw:     mutate(func(b *ngBuilder) { b.idb(1, 0, 6) }),
			wantErr: "not a pcapng or libpcap",
		},
		{
			name: "bad byte-order magic",
			raw: func() []byte {
				raw := canonicalNG(bo)
				raw[8] ^= 0xFF
				return raw
			}(),
			wantErr: "bad byte-order magic",
		},
		{
			name: "unsupported major version",
			raw: func() []byte {
				raw := canonicalNG(bo)
				bo.PutUint16(raw[12:14], 2)
				return raw
			}(),
			wantErr: "unsupported format version",
		},
		{
			name: "trailer length disagrees with header",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				b.idb(1, 0, 6)
				b.epb(0, 0, []byte("data"), 4)
				raw := b.bytes()
				// last 4 bytes are the final block's trailing length
				bo.PutUint32(raw[len(raw)-4:], 999)
				return raw
			}(),
			wantErr: "trailer length",
		},
		{
			name: "block length below the 12-byte envelope",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				raw := b.bytes()
				extra := make([]byte, 12)
				bo.PutUint32(extra[0:4], blockInterfaceDesc)
				bo.PutUint32(extra[4:8], 8) // impossible: < 12
				bo.PutUint32(extra[8:12], 8)
				return append(raw, extra...)
			}(),
			wantErr: "impossible length",
		},
		{
			name: "block length not 32-bit aligned",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				raw := b.bytes()
				extra := make([]byte, 16)
				bo.PutUint32(extra[0:4], blockInterfaceDesc)
				bo.PutUint32(extra[4:8], 13)
				bo.PutUint32(extra[12:16], 13)
				return append(raw, extra...)
			}(),
			wantErr: "impossible length",
		},
		{
			name: "block length over the sanity limit",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				raw := b.bytes()
				extra := make([]byte, 12)
				bo.PutUint32(extra[0:4], blockEnhancedPacket)
				bo.PutUint32(extra[4:8], 0x7FFFFFF0)
				bo.PutUint32(extra[8:12], 0x7FFFFFF0)
				return append(raw, extra...)
			}(),
			wantErr: "over the",
		},
		{
			name: "enhanced packet block names an undescribed interface",
			raw: mutate(func(b *ngBuilder) {
				b.shb()
				b.idb(1, 0, 6)
				b.epb(7, 0, []byte("x"), 1)
			}),
			wantErr: "only 1 are described",
		},
		{
			name: "enhanced packet block before any interface description",
			raw: mutate(func(b *ngBuilder) {
				b.shb()
				b.epb(0, 0, []byte("x"), 1)
			}),
			wantErr: "only 0 are described",
		},
		{
			name: "captured length overruns the block",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				b.idb(1, 0, 6)
				b.epb(0, 0, []byte("data"), 4)
				raw := b.bytes()
				// The EPB is the last block; its captured-length field sits 12
				// bytes past the block start, then 12 more into the body.
				off := len(raw) - 4 /*trailer*/ - 4 /*opt*/ - 4 /*data*/ - 20 /*epb head*/ + 12
				bo.PutUint32(raw[off:off+4], 0x0000FFFF)
				return raw
			}(),
			wantErr: "the block holds",
		},
		{
			name: "simple packet block with no interface",
			raw: mutate(func(b *ngBuilder) {
				b.shb()
				b.spb(4, []byte("data"))
			}),
			wantErr: "before any Interface Description Block",
		},
		{
			name: "option length overruns the block",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				b.idb(1, 0, 6)
				raw := b.bytes()
				bo.PutUint16(raw[optLenOff:optLenOff+2], 4000)
				return raw
			}(),
			wantErr: "option",
		},
		{
			name: "if_tsresol option with the wrong length",
			raw: func() []byte {
				b := newNG(bo)
				b.shb()
				b.idb(1, 0, 6)
				raw := b.bytes()
				bo.PutUint16(raw[optLenOff:optLenOff+2], 4)
				return raw
			}(),
			wantErr: "if_tsresol option is 4 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readAllBytes(t, tc.raw)
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestPcapngTruncationSweep truncates the canonical capture at EVERY byte
// offset and demands two invariants at each one: the reader never panics, and
// whatever packets it does return are a byte-exact prefix of the packets the
// intact file yields. A parser that resynchronised onto misaligned data could
// satisfy "returns an error" while still handing an operator a frame that was
// never on the wire — that is the failure this sweep exists to exclude.
func TestPcapngTruncationSweep(t *testing.T) {
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		full := canonicalNG(bo)
		want, err := readAllBytes(t, full)
		if err != nil {
			t.Fatalf("reference capture does not parse: %v", err)
		}
		for n := 0; n < len(full); n++ {
			got, err := readAllBytes(t, full[:n])
			if err == nil && n != len(full) {
				// Valid prefixes exist (a file that ends on a block boundary is
				// a legal, shorter capture), so a nil error is only suspicious
				// if it came with too many packets — checked below.
				_ = err
			}
			if len(got) > len(want) {
				t.Fatalf("prefix of %d bytes yielded %d packets, more than the intact file's %d", n, len(got), len(want))
			}
			for i := range got {
				if got[i].Index != want[i].Index || !bytes.Equal(got[i].Data, want[i].Data) {
					t.Fatalf("prefix of %d bytes: packet %d differs from the intact file", n, i+1)
				}
			}
		}
	}
}

// TestPcapngStickyError proves a reader that hit a malformed block stays
// broken: no caller can accidentally skip past corruption by looping on Next.
func TestPcapngStickyError(t *testing.T) {
	bo := binary.LittleEndian
	raw := canonicalNG(bo)
	bo.PutUint32(raw[len(raw)-4:], 12345) // corrupt the last block's trailer
	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	var first error
	for {
		if _, err := r.Next(); err != nil {
			first = err
			break
		}
	}
	if first == nil {
		t.Fatal("expected an error from the corrupted capture")
	}
	for i := 0; i < 3; i++ {
		if _, err := r.Next(); err == nil || err.Error() != first.Error() {
			t.Fatalf("Next after error returned %v, want the latched %v", err, first)
		}
	}
}

func TestOpenAndReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "canonical.pcapng")
	if err := os.WriteFile(path, canonicalNG(binary.LittleEndian), 0o644); err != nil {
		t.Fatal(err)
	}
	pkts, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(pkts) != 3 {
		t.Fatalf("got %d packets, want 3", len(pkts))
	}
	if _, err := ReadFile(filepath.Join(dir, "absent.pcapng")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	empty := filepath.Join(dir, "empty.pcapng")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(empty); !errors.Is(err, ErrNotCapture) {
		t.Fatalf("empty file error = %v, want ErrNotCapture", err)
	}
}

// TestReaderNeverReusesBuffers guards the ownership contract on Packet.Data:
// the reassembler retains every segment, so a shared buffer would corrupt
// evidence long after the read that produced it.
func TestReaderNeverReusesBuffers(t *testing.T) {
	pkts, err := readAllBytes(t, canonicalNG(binary.LittleEndian))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	for i := range pkts {
		for j := range pkts {
			if i != j && len(pkts[i].Data) > 0 && &pkts[i].Data[0] == &pkts[j].Data[0] {
				t.Fatalf("packets %d and %d share a backing array", i+1, j+1)
			}
		}
	}
}

func TestReadAllReturnsPacketsBeforeTailError(t *testing.T) {
	bo := binary.LittleEndian
	raw := canonicalNG(bo)
	raw = raw[:len(raw)-2] // chop the last block's trailer in half
	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	pkts, err := ReadAll(r)
	if err == nil {
		t.Fatal("want a truncation error")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want it to wrap io.ErrUnexpectedEOF", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets before the truncation, want the 2 that were complete", len(pkts))
	}
}
