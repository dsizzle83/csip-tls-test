package tlsdis

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// fakeMapper attributes stream offsets to frames on a fixed segment size, so
// the provenance plumbing can be tested without a capture.
type fakeMapper struct{ segment int }

func (m fakeMapper) PacketsFor(start, end int) []int {
	var out []int
	for off := start; off < end; off += m.segment {
		p := off/m.segment + 1
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	if len(out) == 0 && start == end {
		return nil
	}
	// The final byte may fall in a later segment than the last step.
	if last := (end - 1) / m.segment; end > start && (len(out) == 0 || out[len(out)-1] != last+1) {
		out = append(out, last+1)
	}
	return out
}

func TestParseRecordsMultiplePerSegment(t *testing.T) {
	data := join(
		rec(ContentHandshake, VersionTLS12, []byte("AAAA")),
		rec(ContentChangeCipherSpec, VersionTLS12, []byte{1}),
		rec(ContentApplicationData, VersionTLS12, []byte("BBBBBBBB")),
		rec(ContentAlert, VersionTLS12, []byte{2, 48}),
	)
	rs, err := ParseRecords(data, nil)
	if err != nil {
		t.Fatalf("ParseRecords: %v", err)
	}
	if len(rs.Records) != 4 {
		t.Fatalf("got %d records, want 4", len(rs.Records))
	}
	wantTypes := []ContentType{ContentHandshake, ContentChangeCipherSpec, ContentApplicationData, ContentAlert}
	off := 0
	for i, r := range rs.Records {
		if r.Type != wantTypes[i] {
			t.Errorf("record %d type = %s, want %s", i, ContentTypeName(r.Type), ContentTypeName(wantTypes[i]))
		}
		if r.Index != i {
			t.Errorf("record %d has Index %d", i, r.Index)
		}
		if r.Offset != off {
			t.Errorf("record %d Offset = %d, want %d", i, r.Offset, off)
		}
		off = r.End()
	}
	if rs.Trailing != 0 {
		t.Errorf("Trailing = %d, want 0", rs.Trailing)
	}
}

func TestParseRecordsTrailingPartialRecord(t *testing.T) {
	full := rec(ContentApplicationData, VersionTLS12, bytes.Repeat([]byte{7}, 40))
	data := join(rec(ContentHandshake, VersionTLS12, []byte("hi")), full[:20])
	rs, err := ParseRecords(data, nil)
	if err != nil {
		t.Fatalf("ParseRecords: %v", err)
	}
	if len(rs.Records) != 1 {
		t.Fatalf("got %d records, want 1 complete", len(rs.Records))
	}
	if rs.Trailing != 20 {
		t.Errorf("Trailing = %d, want 20", rs.Trailing)
	}
	if rs.Need != 25 {
		t.Errorf("Need = %d, want 25 (5-byte header + 40-byte fragment, minus the 20 present)", rs.Need)
	}
}

func TestParseRecordsRejectsNonTLS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"http response", []byte("HTTP/1.1 200 OK\r\n\r\nbody-bytes-here"), "not a TLS record"},
		{
			name:    "bad version",
			data:    rec(ContentHandshake, 0x0201, []byte("x")),
			wantErr: "not a TLS version",
		},
		{
			name:    "over-long fragment",
			data:    join([]byte{byte(ContentApplicationData)}, u16b(VersionTLS12), u16b(0xFFFF), make([]byte, 10)),
			wantErr: "over the",
		},
		{
			name: "desync after a good record",
			data: join(
				rec(ContentHandshake, VersionTLS12, []byte("ok")),
				[]byte{0x99, 0x03, 0x03, 0x00, 0x01, 0x00},
			),
			wantErr: "content type 153",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRecords(tc.data, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseRecordsKeepsRecordsBeforeDesync(t *testing.T) {
	data := join(
		rec(ContentHandshake, VersionTLS12, []byte("first")),
		rec(ContentHandshake, VersionTLS12, []byte("second")),
		[]byte{0x99, 0x03, 0x03, 0x00, 0x01, 0x00},
	)
	rs, err := ParseRecords(data, nil)
	if err == nil {
		t.Fatal("want a desync error")
	}
	if len(rs.Records) != 2 {
		t.Fatalf("got %d records before the desync, want 2", len(rs.Records))
	}
}

func TestRecordProvenance(t *testing.T) {
	// 10-byte "segments": every 10 stream bytes belong to the next frame.
	data := join(
		rec(ContentHandshake, VersionTLS12, bytes.Repeat([]byte{1}, 20)), // offsets 0..24
		rec(ContentAlert, VersionTLS12, []byte{2, 40}),                   // offsets 25..31
	)
	rs, err := ParseRecords(data, fakeMapper{segment: 10})
	if err != nil {
		t.Fatalf("ParseRecords: %v", err)
	}
	if got := fmt.Sprint(rs.Records[0].Packets); got != "[1 2 3]" {
		t.Errorf("first record frames = %s, want [1 2 3]", got)
	}
	if got := fmt.Sprint(rs.Records[1].Packets); got != "[3 4]" {
		t.Errorf("alert record frames = %s, want [3 4]", got)
	}
	if s := rs.Records[1].String(); !strings.Contains(s, "alert") {
		t.Errorf("Record.String() = %q", s)
	}
}

func TestDirectionAlertsAndCCS(t *testing.T) {
	data := join(
		rec(ContentHandshake, VersionTLS12, hsMsg(HandshakeServerHelloDone, nil)),
		rec(ContentChangeCipherSpec, VersionTLS12, []byte{1}),
		rec(ContentAlert, VersionTLS12, []byte{2, 48}), // fatal unknown_ca
		rec(ContentAlert, VersionTLS12, []byte{1, 0}),  // warning close_notify
	)
	d, err := ParseDirection(data, fakeMapper{segment: 8})
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	if len(d.CCS) != 1 || d.CCS[0] != 1 {
		t.Errorf("CCS = %v, want [1]", d.CCS)
	}
	if len(d.Alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(d.Alerts))
	}
	fatal, ok := d.FatalAlert()
	if !ok {
		t.Fatal("FatalAlert not found")
	}
	if fatal.Description != 48 || !fatal.Fatal() {
		t.Errorf("fatal alert = %+v", fatal)
	}
	if got, want := AlertDescriptionName(fatal.Description), "unknown_ca"; got != want {
		t.Errorf("description name = %q, want %q", got, want)
	}
	if len(fatal.Packets) == 0 {
		t.Error("a fatal alert must carry the frames it was seen in — it is the evidence")
	}
	if !strings.Contains(fatal.String(), "fatal unknown_ca") {
		t.Errorf("Alert.String() = %q", fatal.String())
	}
	// The handshake parse must stop at the ChangeCipherSpec.
	if len(d.Handshake.Messages) != 1 {
		t.Fatalf("got %d handshake messages, want 1 (parsing must stop at CCS)", len(d.Handshake.Messages))
	}
}

func TestMultipleAlertsInOneRecord(t *testing.T) {
	data := rec(ContentAlert, VersionTLS12, []byte{1, 0, 2, 40})
	d, err := ParseDirection(data, nil)
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	if len(d.Alerts) != 2 {
		t.Fatalf("got %d alerts, want 2", len(d.Alerts))
	}
	if d.Alerts[0].Offset != 5 || d.Alerts[1].Offset != 7 {
		t.Errorf("alert offsets = %d,%d, want 5,7", d.Alerts[0].Offset, d.Alerts[1].Offset)
	}
}

// TestHandshakeStopsAtChangeCipherSpec proves the second parsing rule: bytes
// after a CCS are ciphertext, and feeding them to the handshake parser would
// report AEAD output as handshake structure.
func TestHandshakeStopsAtChangeCipherSpec(t *testing.T) {
	data := join(
		rec(ContentHandshake, VersionTLS12, hsMsg(HandshakeServerHelloDone, nil)),
		rec(ContentChangeCipherSpec, VersionTLS12, []byte{1}),
		// Random ciphertext that happens to start with a plausible handshake type.
		rec(ContentHandshake, VersionTLS12, join([]byte{0x0B}, u24b(9), bytes.Repeat([]byte{0xAB}, 9))),
	)
	d, err := ParseDirection(data, nil)
	if err != nil {
		t.Fatalf("ParseDirection: %v", err)
	}
	if got := d.Handshake.Types(); len(got) != 1 || got[0] != HandshakeServerHelloDone {
		t.Fatalf("handshake types = %v, want just server_hello_done", got)
	}
}

func TestMaxRecordFragmentBoundary(t *testing.T) {
	ok := rec(ContentApplicationData, VersionTLS12, make([]byte, MaxRecordFragment))
	if _, err := ParseRecords(ok, nil); err != nil {
		t.Fatalf("a record at exactly the maximum must parse: %v", err)
	}
	over := join([]byte{byte(ContentApplicationData)}, u16b(VersionTLS12), u16b(MaxRecordFragment+1), make([]byte, MaxRecordFragment+1))
	if _, err := ParseRecords(over, nil); err == nil {
		t.Fatal("a record one byte over the maximum must be rejected")
	}
}
