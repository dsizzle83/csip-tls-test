package pcapng

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// pcBuilder lays out a classic libpcap file by hand. The four (magic, byte
// order) pairs are the whole point: tcpdump on a big-endian device and tcpdump
// on the desktop write the same logical capture with the fields reversed, and
// an evidence reader that only understood the local ordering would report a
// remote bench's capture as garbage.
type pcBuilder struct {
	bo   binary.ByteOrder
	nano bool
	buf  []byte
}

func newPC(bo binary.ByteOrder, nano bool) *pcBuilder {
	b := &pcBuilder{bo: bo, nano: nano}
	magic := uint32(pcapMagicMicro)
	if nano {
		magic = pcapMagicNano
	}
	hdr := make([]byte, pcapFileHeaderLen)
	// The magic is written in the file's own byte order; a reader that reads it
	// big-endian sees either the constant or its byte-swapped twin.
	bo.PutUint32(hdr[0:4], magic)
	bo.PutUint16(hdr[4:6], 2)
	bo.PutUint16(hdr[6:8], 4)
	bo.PutUint32(hdr[8:12], 0)      // thiszone
	bo.PutUint32(hdr[12:16], 0)     // sigfigs
	bo.PutUint32(hdr[16:20], 65535) // snaplen
	bo.PutUint32(hdr[20:24], 1)     // LINKTYPE_ETHERNET
	b.buf = hdr
	return b
}

func (b *pcBuilder) packet(sec, frac uint32, data []byte, origLen uint32) {
	hdr := make([]byte, pcapRecordHeaderLen)
	b.bo.PutUint32(hdr[0:4], sec)
	b.bo.PutUint32(hdr[4:8], frac)
	b.bo.PutUint32(hdr[8:12], uint32(len(data)))
	b.bo.PutUint32(hdr[12:16], origLen)
	b.buf = append(b.buf, hdr...)
	b.buf = append(b.buf, data...)
}

func (b *pcBuilder) bytes() []byte { return b.buf }

func canonicalPC(bo binary.ByteOrder, nano bool) []byte {
	b := newPC(bo, nano)
	frac := uint32(250_000)
	if nano {
		frac = 250_000_000
	}
	b.packet(1_700_000_000, frac, []byte("alpha"), 5)
	b.packet(1_700_000_001, 0, []byte("bravo-truncated"), 1500)
	return b.bytes()
}

func TestPcapAllFourVariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		bo   binary.ByteOrder
		nano bool
	}{
		{"little-endian microsecond", binary.LittleEndian, false},
		{"big-endian microsecond", binary.BigEndian, false},
		{"little-endian nanosecond", binary.LittleEndian, true},
		{"big-endian nanosecond", binary.BigEndian, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewReader(bytes.NewReader(canonicalPC(tc.bo, tc.nano)))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if r.Format() != FormatPcap {
				t.Fatalf("Format = %q, want %q", r.Format(), FormatPcap)
			}
			pkts, err := ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if len(pkts) != 2 {
				t.Fatalf("got %d packets, want 2", len(pkts))
			}
			if got := string(pkts[0].Data); got != "alpha" {
				t.Errorf("packet 1 data = %q", got)
			}
			want := time.Unix(1_700_000_000, 250_000_000).UTC()
			if !pkts[0].Time.Equal(want) {
				t.Errorf("packet 1 time = %v, want %v", pkts[0].Time, want)
			}
			if pkts[0].LinkType != 1 {
				t.Errorf("LinkType = %d, want 1", pkts[0].LinkType)
			}
			if !pkts[1].Truncated() || pkts[1].OrigLen != 1500 {
				t.Errorf("packet 2 should be snaplen-truncated: len=%d origLen=%d", len(pkts[1].Data), pkts[1].OrigLen)
			}
			if pkts[1].Index != 2 {
				t.Errorf("packet 2 Index = %d, want 2", pkts[1].Index)
			}
		})
	}
}

// TestPcapLinkTypeWithFCSHint proves the reader masks off the FCS-length hint
// libpcap packs into the top bits of the "network" field rather than reporting
// a link type of 0x1000_0001.
func TestPcapLinkTypeWithFCSHint(t *testing.T) {
	raw := canonicalPC(binary.LittleEndian, false)
	binary.LittleEndian.PutUint32(raw[20:24], 0x1000_0001)
	pkts, err := readAllBytes(t, raw)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if pkts[0].LinkType != 1 {
		t.Fatalf("LinkType = %d, want 1", pkts[0].LinkType)
	}
}

func TestPcapMalformed(t *testing.T) {
	bo := binary.LittleEndian
	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{
			name:    "unknown magic",
			raw:     append([]byte{0xDE, 0xAD, 0xBE, 0xEF}, bytes.Repeat([]byte{0}, 40)...),
			wantErr: "not a known libpcap magic",
		},
		{
			name:    "header shorter than 24 bytes",
			raw:     canonicalPC(bo, false)[:20],
			wantErr: "too short for a 24-byte libpcap header",
		},
		{
			name: "unsupported major version",
			raw: func() []byte {
				raw := canonicalPC(bo, false)
				bo.PutUint16(raw[4:6], 3)
				return raw
			}(),
			wantErr: "unsupported libpcap version",
		},
		{
			name: "record longer than the file snaplen",
			raw: func() []byte {
				raw := canonicalPC(bo, false)
				bo.PutUint32(raw[pcapFileHeaderLen+8:pcapFileHeaderLen+12], 70000)
				return raw
			}(),
			wantErr: "over the file's snaplen",
		},
		{
			name: "record promises more data than the file holds",
			raw: func() []byte {
				raw := canonicalPC(bo, false)
				bo.PutUint32(raw[pcapFileHeaderLen+8:pcapFileHeaderLen+12], 60000)
				bo.PutUint32(raw[16:20], 65535)
				return raw
			}(),
			wantErr: "libpcap record data",
		},
		{
			name: "timestamp fraction out of range",
			raw: func() []byte {
				raw := canonicalPC(bo, false)
				bo.PutUint32(raw[pcapFileHeaderLen+4:pcapFileHeaderLen+8], 2_000_000)
				return raw
			}(),
			wantErr: "timestamp fraction",
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

func TestPcapTruncationSweep(t *testing.T) {
	for _, nano := range []bool{false, true} {
		for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			full := canonicalPC(bo, nano)
			want, err := readAllBytes(t, full)
			if err != nil {
				t.Fatalf("reference capture does not parse: %v", err)
			}
			for n := 0; n < len(full); n++ {
				got, err := readAllBytes(t, full[:n])
				_ = err // an error is expected at most offsets; the invariant is the prefix property
				if len(got) > len(want) {
					t.Fatalf("prefix of %d bytes yielded %d packets, more than the intact file's %d", n, len(got), len(want))
				}
				for i := range got {
					if !bytes.Equal(got[i].Data, want[i].Data) {
						t.Fatalf("prefix of %d bytes: packet %d differs from the intact file", n, i+1)
					}
				}
			}
		}
	}
}

func TestPcapTruncatedFinalRecord(t *testing.T) {
	raw := canonicalPC(binary.LittleEndian, false)
	raw = raw[:len(raw)-3]
	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	pkts, err := ReadAll(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want it to wrap io.ErrUnexpectedEOF", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want the 1 complete record", len(pkts))
	}
}

// FuzzReader is the standing guarantee behind the package doc's promise that
// malformed input never panics. The seed corpus is every fixture the unit tests
// build; `go test -run=Fuzz -fuzz=FuzzReader ./internal/evidence/pcapng/` extends
// it, and the seeds alone run on every `go test`.
func FuzzReader(f *testing.F) {
	f.Add(canonicalNG(binary.LittleEndian))
	f.Add(canonicalNG(binary.BigEndian))
	f.Add(canonicalPC(binary.LittleEndian, false))
	f.Add(canonicalPC(binary.BigEndian, true))
	f.Add([]byte{})
	f.Add([]byte{0x0A, 0x0D, 0x0D, 0x0A})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		for i := 0; i < 10_000; i++ {
			p, err := r.Next()
			if err != nil {
				return
			}
			if len(p.Data) > p.OrigLen {
				t.Fatalf("captured %d bytes but reported an original length of %d", len(p.Data), p.OrigLen)
			}
		}
	})
}
