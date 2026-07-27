package tlsdis

import (
	"fmt"
)

// ContentType is the TLS record layer's content type.
type ContentType uint8

// TLS record content types.
const (
	ContentChangeCipherSpec ContentType = 20
	ContentAlert            ContentType = 21
	ContentHandshake        ContentType = 22
	ContentApplicationData  ContentType = 23
	ContentHeartbeat        ContentType = 24
)

// MaxRecordFragment is the largest TLSCiphertext.length any TLS version
// permits: 2^14 plaintext bytes plus 2048 bytes of expansion (TLS 1.2's
// generous bound; TLS 1.3 allows only 256). A larger length field means the
// stream is not TLS, or is no longer synchronised with it.
const MaxRecordFragment = 1<<14 + 2048

// OffsetMapper resolves a byte range of a reassembled stream to the capture
// frames that carried it. netdis.StreamBytes implements it; passing nil is
// allowed and simply leaves Packets empty (useful when parsing a hand-built
// fixture that never came off a wire).
type OffsetMapper interface {
	PacketsFor(start, end int) []int
}

// Record is one TLS record as it sat in the byte stream.
type Record struct {
	Index    int         // position in this direction's record list, 0-based
	Offset   int         // byte offset of the record header in the reassembled stream
	Type     ContentType // the OUTER content type; for TLS 1.3 this is a cover story
	Version  uint16      // legacy_record_version — informational after TLS 1.2
	Length   int         // fragment length
	Fragment []byte      // the fragment bytes, still encrypted if the epoch is
	Packets  []int       // frames carrying this record, header included
}

// End returns the stream offset just past this record.
func (r Record) End() int { return r.Offset + 5 + r.Length }

func (r Record) String() string {
	return fmt.Sprintf("record %d at %d: %s len=%d %s frames=%v",
		r.Index, r.Offset, ContentTypeName(r.Type), r.Length, VersionName(r.Version), r.Packets)
}

// RecordStream is one direction's record layer.
type RecordStream struct {
	Records []Record
	// Trailing counts bytes after the last complete record. A capture that was
	// stopped mid-record leaves them; so does a connection that was still in
	// flight. Either way they are reported rather than parsed.
	Trailing int
	// Need is how many more bytes the incomplete trailing record wanted, so a
	// report can say "the capture is 42 bytes short of the final record" rather
	// than just "truncated".
	Need int
}

// ParseRecords walks the record layer of one direction's reassembled stream.
//
// It is strict about the record header because record framing is the anchor for
// every offset the bundle cites: once a parser guesses past a bad header, every
// subsequent byte offset in the report is fiction. A header that is not a
// plausible TLS record aborts with the offset it failed at, and the records
// parsed up to that point are still returned.
func ParseRecords(data []byte, m OffsetMapper) (*RecordStream, error) {
	rs := &RecordStream{}
	off := 0
	for {
		if len(data)-off < 5 {
			rs.Trailing = len(data) - off
			if rs.Trailing > 0 {
				rs.Need = 5 - rs.Trailing
			}
			return rs, nil
		}
		ct := ContentType(data[off])
		version := uint16(data[off+1])<<8 | uint16(data[off+2])
		length := int(data[off+3])<<8 | int(data[off+4])

		if ct < ContentChangeCipherSpec || ct > ContentHeartbeat {
			return rs, fmt.Errorf("tlsdis: byte at stream offset %d is content type %d, not a TLS record", off, ct)
		}
		if version>>8 != 0x03 {
			return rs, fmt.Errorf("tlsdis: record at stream offset %d declares version 0x%04X, not a TLS version", off, version)
		}
		if length > MaxRecordFragment {
			return rs, fmt.Errorf("tlsdis: record at stream offset %d declares a %d-byte fragment, over the %d-byte maximum",
				off, length, MaxRecordFragment)
		}
		if len(data)-off-5 < length {
			rs.Trailing = len(data) - off
			rs.Need = 5 + length - rs.Trailing
			return rs, nil
		}

		rec := Record{
			Index:    len(rs.Records),
			Offset:   off,
			Type:     ct,
			Version:  version,
			Length:   length,
			Fragment: data[off+5 : off+5+length],
		}
		if m != nil {
			rec.Packets = m.PacketsFor(off, off+5+length)
		}
		rs.Records = append(rs.Records, rec)
		off += 5 + length
	}
}

// Alert is one alert, with the frames that carried it.
//
// Fatal-alert evidence is the pass criterion for the negative test cases
// (SunSpecTCP-13: "server MUST send a fatal alert and terminate if the client
// sends no certificate"), which is why an Alert carries its frame list rather
// than just its codepoints.
type Alert struct {
	Level       uint8
	Description uint8
	Record      int // record index within the direction
	Offset      int // stream offset of the alert's first byte
	Packets     []int
}

// Fatal reports whether the alert's level is fatal(2).
func (a Alert) Fatal() bool { return a.Level == 2 }

func (a Alert) String() string {
	return fmt.Sprintf("%s %s (level %d, desc %d) in frame(s) %v",
		AlertLevelName(a.Level), AlertDescriptionName(a.Description), a.Level, a.Description, a.Packets)
}

// Direction is a parsed view of one side's TLS byte stream.
type Direction struct {
	Stream *RecordStream

	// Handshake holds the plaintext handshake, coalesced ACROSS records. It
	// stops at the first ChangeCipherSpec: everything after that is encrypted
	// and only tlsdecrypt can produce more.
	Handshake *HandshakeStream

	// CCS lists the record indices of ChangeCipherSpec records. In TLS 1.3 it
	// is a middlebox-compatibility no-op that carries no key change at all, and
	// notably does NOT advance the record sequence number — a fact tlsdecrypt
	// depends on.
	CCS []int

	// Alerts holds every alert visible in plaintext. Alerts sent after the
	// handshake completes are encrypted and appear here only once decrypted.
	Alerts []Alert

	// AppData lists the record indices carrying application data (or, in TLS
	// 1.3, everything after the handshake, since the outer type is a cover).
	AppData []int
}

// ParseDirection parses one direction's reassembled TCP stream: the record
// layer, the plaintext handshake, and the alerts.
func ParseDirection(data []byte, m OffsetMapper) (*Direction, error) {
	rs, err := ParseRecords(data, m)
	d := &Direction{Stream: rs}
	if rs != nil {
		d.classify()
	}
	// The handshake is parsed even when the record layer failed part-way: the
	// records that WERE recovered are still evidence, and a caller that checked
	// the error first would otherwise be handed a Direction with a nil
	// Handshake to dereference.
	hs, hsErr := ParseHandshake(d.HandshakeFragments(), Options{})
	d.Handshake = hs
	if err != nil {
		return d, err
	}
	return d, hsErr
}

// classify splits the record list by content type and pulls out the alerts.
func (d *Direction) classify() {
	for _, rec := range d.Stream.Records {
		switch rec.Type {
		case ContentChangeCipherSpec:
			d.CCS = append(d.CCS, rec.Index)
		case ContentApplicationData:
			d.AppData = append(d.AppData, rec.Index)
		case ContentAlert:
			// An alert record is a sequence of 2-byte alerts. In practice there
			// is exactly one, but the record layer permits more and a report
			// that showed only the first would understate what was sent.
			for i := 0; i+1 < len(rec.Fragment); i += 2 {
				d.Alerts = append(d.Alerts, Alert{
					Level:       rec.Fragment[i],
					Description: rec.Fragment[i+1],
					Record:      rec.Index,
					Offset:      rec.Offset + 5 + i,
					Packets:     rec.Packets,
				})
			}
		}
	}
}

// HandshakeFragments returns the plaintext handshake fragments of this
// direction, in order, stopping at the first ChangeCipherSpec.
//
// This is REQUIREMENT ONE of handshake parsing and the single most common way
// to get TLS dissection wrong: the handshake is a byte stream layered OVER the
// record layer (RFC 8446 §5.1), not a sequence of self-contained records. A
// 1396-byte Certificate arrives as three fragments, and a message header can be
// split down the middle — the length field's high byte in one record and its
// low bytes in the next. A parser that walks messages inside each record
// independently reads the next record's first four bytes as a length and
// reports a multi-megabyte "message". Coalesce first, parse second.
func (d *Direction) HandshakeFragments() []Fragment {
	stop := -1
	if len(d.CCS) > 0 {
		stop = d.CCS[0]
	}
	var frags []Fragment
	for _, rec := range d.Stream.Records {
		if stop >= 0 && rec.Index >= stop {
			break
		}
		if rec.Type != ContentHandshake {
			continue
		}
		frags = append(frags, Fragment{
			Data:    rec.Fragment,
			Record:  rec.Index,
			Packets: rec.Packets,
		})
	}
	return frags
}

// FatalAlert returns the first fatal alert of the direction, if any.
func (d *Direction) FatalAlert() (Alert, bool) {
	for _, a := range d.Alerts {
		if a.Fatal() {
			return a, true
		}
	}
	return Alert{}, false
}
