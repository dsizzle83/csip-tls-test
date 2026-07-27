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
	// Level and Description are the alert's two codepoints — and they are only
	// meaningful when Encrypted is false. See Encrypted.
	Level       uint8
	Description uint8
	// Encrypted marks an alert record whose BODY is ciphertext: it was sent
	// after this direction's ChangeCipherSpec, so the two bytes at its start
	// are AEAD output, not a level and a description. Level and Description are
	// left zero in that case and must not be reported.
	//
	// This is not a refinement. Reading those bytes anyway is wrong in both
	// directions at once: a ciphertext byte that happens to be 0x02 fabricates
	// a fatal alert nobody sent, and a REAL encrypted fatal alert reads as
	// whatever its first ciphertext byte happens to be — usually "not fatal".
	// A tool that does it hands out a clean bill on a device that failed. The
	// alert is still reported, with its frames, so a check can say "an
	// encrypted alert record is present at frame N" and decide what that is
	// worth; recovering the codepoints needs the session keys and belongs to
	// internal/evidence/tlsdecrypt.
	Encrypted bool
	Record    int // record index within the direction
	Offset    int // stream offset of the alert's first byte
	Packets   []int
}

// Fatal reports whether the alert's level is fatal(2).
//
// An encrypted alert is never fatal HERE, because here it is unknown: only
// tlsdecrypt can say. Callers that must not miss a fatal alert should treat a
// direction's EncryptedAlerts as "undetermined" rather than as "none".
func (a Alert) Fatal() bool { return !a.Encrypted && a.Level == 2 }

func (a Alert) String() string {
	if a.Encrypted {
		return fmt.Sprintf("encrypted alert record %d at %d (level and description are ciphertext) in frame(s) %v",
			a.Record, a.Offset, a.Packets)
	}
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

	// Alerts holds every alert record of the direction, in order. The ones
	// before the first ChangeCipherSpec carry a decoded Level and Description;
	// the ones after it are marked Encrypted and carry neither, because their
	// bodies are ciphertext. Both are listed: an alert record's EXISTENCE is
	// visible in the clear even when its content is not, and dropping the
	// encrypted ones would report "no alert" for a connection that was torn
	// down by one.
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
//
// The ChangeCipherSpec boundary governs the alerts exactly as it governs the
// handshake: before it the fragment is an alert body, after it the fragment is
// AEAD output that merely has the alert content type on its header. Records
// after the boundary are recorded as alerts-of-unknown-content rather than
// decoded — see Alert.Encrypted for what decoding them anyway would produce.
func (d *Direction) classify() {
	encrypted := false
	for _, rec := range d.Stream.Records {
		switch rec.Type {
		case ContentChangeCipherSpec:
			d.CCS = append(d.CCS, rec.Index)
			encrypted = true
		case ContentApplicationData:
			d.AppData = append(d.AppData, rec.Index)
		case ContentAlert:
			if encrypted {
				// One entry per RECORD, not per two bytes: the number of alerts
				// inside a ciphertext is itself unknown, and inventing a count
				// from the fragment length would be another guess.
				d.Alerts = append(d.Alerts, Alert{
					Encrypted: true,
					Record:    rec.Index,
					Offset:    rec.Offset + 5,
					Packets:   rec.Packets,
				})
				continue
			}
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
//
// "if any" means "if any that this package can read". A false return with a
// non-empty EncryptedAlerts means UNDETERMINED, not absent — see EncryptedAlerts.
func (d *Direction) FatalAlert() (Alert, bool) {
	for _, a := range d.Alerts {
		if a.Fatal() {
			return a, true
		}
	}
	return Alert{}, false
}

// PlainAlerts returns the alerts whose level and description were readable —
// those sent before this direction's first ChangeCipherSpec.
func (d *Direction) PlainAlerts() []Alert {
	var out []Alert
	for _, a := range d.Alerts {
		if !a.Encrypted {
			out = append(out, a)
		}
	}
	return out
}

// EncryptedAlerts returns the alert records whose bodies are ciphertext.
//
// A check that concludes "the peer sent no fatal alert" while this is non-empty
// is asserting something the capture alone cannot support: the peer may have
// sent exactly that alert. Decrypt with the run's key log, or say the alert is
// encrypted and cite the frames — but do not call it an absence.
func (d *Direction) EncryptedAlerts() []Alert {
	var out []Alert
	for _, a := range d.Alerts {
		if a.Encrypted {
			out = append(out, a)
		}
	}
	return out
}
