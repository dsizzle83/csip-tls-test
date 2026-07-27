package tlsdecrypt

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/tlsdis"
)

// Side names one direction of a connection.
type Side int

// The two sides.
const (
	Client Side = iota
	Server
)

func (s Side) String() string {
	if s == Client {
		return "client"
	}
	return "server"
}

// Epoch names which set of keys a direction is using.
type Epoch int

// Key epochs, in the order a connection passes through them.
const (
	// EpochPlaintext: records are not encrypted yet (ClientHello, ServerHello,
	// and in TLS 1.2 everything up to that side's ChangeCipherSpec).
	EpochPlaintext Epoch = iota
	// EpochHandshake: TLS 1.3 handshake traffic secrets.
	EpochHandshake
	// EpochApplication: application traffic secrets (all of TLS 1.2's
	// encrypted records, and TLS 1.3's after Finished).
	EpochApplication
)

func (e Epoch) String() string {
	switch e {
	case EpochPlaintext:
		return "plaintext"
	case EpochHandshake:
		return "handshake"
	default:
		return "application"
	}
}

// Params identifies the session to decrypt. ServerRandom is required for TLS
// 1.2 (it seeds the key block) and ignored for TLS 1.3.
type Params struct {
	Version      uint16
	CipherSuite  uint16
	ClientRandom []byte
	ServerRandom []byte
}

// Plaintext is one recovered record.
type Plaintext struct {
	Side Side
	// Type is the REAL content type: for TLS 1.3 that is the inner type
	// recovered from the end of the decrypted payload, not the record header's
	// application_data cover story.
	Type   tlsdis.ContentType
	Data   []byte
	Record tlsdis.Record
	Seq    uint64
	Epoch  Epoch
	// Encrypted is false for records that were already in the clear.
	Encrypted bool
	// EpochRecovered is set when the record only decrypted after the engine
	// re-tried with the next epoch — a signal that the Finished message that
	// should have triggered the switch was not observed (a truncated capture,
	// usually). The plaintext is authentic either way; the AEAD tag says so.
	EpochRecovered bool
}

// Frames returns the capture frames the record occupied.
func (p Plaintext) Frames() []int { return p.Record.Packets }

// Error is a decryption failure with every fact needed to diagnose it.
//
// The rule this type exists to enforce: a failed record is reported loudly,
// naming the record, the sequence number and the epoch, and NOTHING is
// returned as plaintext. Silent partial output from an evidence tool would be
// worse than no output at all.
type Error struct {
	Side        Side
	RecordIndex int
	Offset      int
	Frames      []int
	Seq         uint64
	Epoch       Epoch
	Reason      string
	Err         error
}

func (e *Error) Error() string {
	return fmt.Sprintf("tlsdecrypt: %s record %d (stream offset %d, frames %v, seq %d, %s keys): %s",
		e.Side, e.RecordIndex, e.Offset, e.Frames, e.Seq, e.Epoch, e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

// dirState is one direction's record-protection state.
type dirState struct {
	side  Side
	epoch Epoch
	seq   uint64

	aead cipher.AEAD
	iv   []byte

	// secret is the current TLS 1.3 traffic secret, kept so a KeyUpdate can
	// advance it. Generation counts how many updates have been applied.
	secret     []byte
	generation int

	// handshakeSecret / applicationSecret are the TLS 1.3 secrets from the key
	// log, retained so the epoch switch can install the next set.
	handshakeSecret   []byte
	applicationSecret []byte

	// tls12Key / tls12IV are installed at that side's ChangeCipherSpec.
	tls12Key []byte
	tls12IV  []byte

	// hsFrags accumulates every handshake fragment this side produced, in
	// order — plaintext and decrypted alike. Handshake messages are parsed from
	// the concatenation of these, never from a single record.
	hsFrags []tlsdis.Fragment
	// hsBuf/hsScanned drive the incremental scan that spots Finished and
	// KeyUpdate, which are the two messages that change keys.
	hsBuf     []byte
	hsScanned int

	pendingEpochSwitch bool
	pendingKeyUpdate   bool
}

// Session decrypts one TLS connection's records.
//
// Records must be fed in capture order, per direction, because the record
// sequence number is implicit: it is a counter, not a field on the wire. A
// caller that skipped a record would silently decrypt every subsequent one with
// the wrong nonce.
type Session struct {
	Params Params
	Suite  suiteParams
	tls13  bool
	dirs   [2]*dirState
}

// New builds a Session from the negotiated parameters and a key log.
func New(p Params, kl *keylog.Log) (*Session, error) {
	if kl == nil {
		return nil, fmt.Errorf("tlsdecrypt: no key log supplied")
	}
	if len(p.ClientRandom) != 32 {
		return nil, fmt.Errorf("tlsdecrypt: client random is %d bytes, want 32", len(p.ClientRandom))
	}
	suite, err := suiteFor(p.Version, p.CipherSuite)
	if err != nil {
		return nil, err
	}
	s := &Session{Params: p, Suite: suite, tls13: p.Version == tlsdis.VersionTLS13}
	for i := range s.dirs {
		s.dirs[i] = &dirState{side: Side(i), epoch: EpochPlaintext}
	}

	if s.tls13 {
		if err := s.initTLS13(kl); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.initTLS12(kl); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) initTLS13(kl *keylog.Log) error {
	type binding struct {
		side           Side
		handshakeLabel string
		appLabel       string
	}
	for _, b := range []binding{
		{Client, keylog.LabelClientHandshake, keylog.LabelClientTraffic0},
		{Server, keylog.LabelServerHandshake, keylog.LabelServerTraffic0},
	} {
		d := s.dirs[b.side]
		d.handshakeSecret, _ = kl.Secret(b.handshakeLabel, s.Params.ClientRandom)
		d.applicationSecret, _ = kl.Secret(b.appLabel, s.Params.ClientRandom)
		switch {
		case d.handshakeSecret != nil:
			if err := s.install(d, EpochHandshake, d.handshakeSecret); err != nil {
				return err
			}
		case d.applicationSecret != nil:
			// A key log that only carries application secrets still decrypts
			// the application data, which is often all a test case needs.
			if err := s.install(d, EpochApplication, d.applicationSecret); err != nil {
				return err
			}
		default:
			return fmt.Errorf("tlsdecrypt: key log has no %s or %s for client random %x",
				b.handshakeLabel, b.appLabel, s.Params.ClientRandom)
		}
	}
	return nil
}

func (s *Session) initTLS12(kl *keylog.Log) error {
	if len(s.Params.ServerRandom) != 32 {
		return fmt.Errorf("tlsdecrypt: TLS 1.2 needs the 32-byte server random to derive the key block, got %d bytes",
			len(s.Params.ServerRandom))
	}
	master, ok := kl.MasterSecret(s.Params.ClientRandom)
	if !ok {
		return fmt.Errorf("tlsdecrypt: key log has no %s entry for client random %x",
			keylog.LabelClientRandom, s.Params.ClientRandom)
	}
	if len(master) != 48 {
		return fmt.Errorf("tlsdecrypt: master secret is %d bytes, want 48", len(master))
	}
	ck, sk, civ, siv := keyBlock12(s.Suite, master, s.Params.ClientRandom, s.Params.ServerRandom)
	s.dirs[Client].tls12Key, s.dirs[Client].tls12IV = ck, civ
	s.dirs[Server].tls12Key, s.dirs[Server].tls12IV = sk, siv
	return nil
}

// install builds the AEAD for an epoch from a TLS 1.3 traffic secret and resets
// the sequence number, which RFC 8446 §5.3 requires on every key change.
func (s *Session) install(d *dirState, epoch Epoch, secret []byte) error {
	key, iv, err := trafficKeys(s.Suite.Hash, secret, s.Suite.KeyLen, s.Suite.FixedIVLen)
	if err != nil {
		return err
	}
	a, err := s.Suite.New(key)
	if err != nil {
		return fmt.Errorf("tlsdecrypt: build %s AEAD: %w", s.Suite.Name, err)
	}
	d.aead, d.iv, d.secret, d.epoch, d.seq = a, iv, secret, epoch, 0
	return nil
}

// Decrypt recovers one record. Records of a direction must be passed in order.
func (s *Session) Decrypt(side Side, rec tlsdis.Record) (*Plaintext, error) {
	d := s.dirs[side]

	// A ChangeCipherSpec is never encrypted, and — the detail that breaks
	// naive implementations — it does NOT advance the record sequence number.
	// In TLS 1.3 it is a middlebox-compatibility no-op that may appear in the
	// middle of the encrypted flight; counting it would put every subsequent
	// nonce off by one.
	if rec.Type == tlsdis.ContentChangeCipherSpec {
		if !s.tls13 {
			if err := s.startTLS12Encryption(d); err != nil {
				return nil, &Error{Side: side, RecordIndex: rec.Index, Offset: rec.Offset,
					Frames: rec.Packets, Epoch: d.epoch, Reason: err.Error(), Err: err}
			}
		}
		return &Plaintext{Side: side, Type: rec.Type, Data: rec.Fragment, Record: rec, Seq: d.seq, Epoch: d.epoch}, nil
	}

	if !s.isEncrypted(d, rec) {
		p := &Plaintext{Side: side, Type: rec.Type, Data: rec.Fragment, Record: rec, Seq: d.seq, Epoch: EpochPlaintext}
		s.noteHandshake(d, p)
		return p, nil
	}

	plain, inner, recovered, err := s.open(d, rec)
	if err != nil {
		return nil, err
	}
	p := &Plaintext{
		Side: side, Type: inner, Data: plain, Record: rec,
		Seq: d.seq, Epoch: d.epoch, Encrypted: true, EpochRecovered: recovered,
	}
	d.seq++
	s.noteHandshake(d, p)
	s.applyPending(d)
	return p, nil
}

// DecryptAll runs Decrypt over a whole direction, stopping at the first
// failure and returning what was recovered before it.
func (s *Session) DecryptAll(side Side, recs []tlsdis.Record) ([]Plaintext, error) {
	out := make([]Plaintext, 0, len(recs))
	for _, rec := range recs {
		p, err := s.Decrypt(side, rec)
		if err != nil {
			return out, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// isEncrypted decides whether a record needs the AEAD.
func (s *Session) isEncrypted(d *dirState, rec tlsdis.Record) bool {
	if s.tls13 {
		// Everything protected in TLS 1.3 is disguised as application_data;
		// anything else on the wire (ClientHello, ServerHello, an early alert)
		// is genuinely in the clear.
		return rec.Type == tlsdis.ContentApplicationData
	}
	return d.epoch != EpochPlaintext
}

// startTLS12Encryption installs the key block at that side's CCS.
func (s *Session) startTLS12Encryption(d *dirState) error {
	if d.epoch != EpochPlaintext {
		return nil // a second CCS (renegotiation) reuses the same keys here
	}
	a, err := s.Suite.New(d.tls12Key)
	if err != nil {
		return fmt.Errorf("build %s AEAD: %w", s.Suite.Name, err)
	}
	d.aead, d.iv, d.epoch, d.seq = a, d.tls12IV, EpochApplication, 0
	return nil
}

// open decrypts one record, retrying once with the next epoch if the current
// one fails.
func (s *Session) open(d *dirState, rec tlsdis.Record) (plain []byte, inner tlsdis.ContentType, recovered bool, err error) {
	plain, inner, err = s.openWith(d, rec)
	if err == nil {
		return plain, inner, false, nil
	}
	// Recovery: a capture that lost the record carrying Finished leaves this
	// direction on handshake keys when the peer has already moved on. Trying
	// the application epoch is safe — a wrong key cannot forge a valid tag, so
	// success here is proof, not a guess.
	if s.tls13 && d.epoch == EpochHandshake && d.applicationSecret != nil {
		saved := *d
		if instErr := s.install(d, EpochApplication, d.applicationSecret); instErr == nil {
			if plain2, inner2, err2 := s.openWith(d, rec); err2 == nil {
				return plain2, inner2, true, nil
			}
		}
		*d = saved
	}
	return nil, 0, false, err
}

func (s *Session) openWith(d *dirState, rec tlsdis.Record) ([]byte, tlsdis.ContentType, error) {
	fail := func(reason string, err error) ([]byte, tlsdis.ContentType, error) {
		return nil, 0, &Error{
			Side: d.side, RecordIndex: rec.Index, Offset: rec.Offset, Frames: rec.Packets,
			Seq: d.seq, Epoch: d.epoch, Reason: reason, Err: err,
		}
	}
	if d.aead == nil {
		return fail("no keys are installed for this direction", nil)
	}

	if s.tls13 {
		nonce := xorSeq(d.iv, d.seq)
		aad := []byte{byte(rec.Type), byte(rec.Version >> 8), byte(rec.Version), byte(rec.Length >> 8), byte(rec.Length)}
		out, err := d.aead.Open(nil, nonce, rec.Fragment, aad)
		if err != nil {
			return fail(fmt.Sprintf("AEAD authentication failed (%s, %d-byte fragment)", s.Suite.Name, rec.Length), err)
		}
		// RFC 8446 §5.2: strip zero padding; the last non-zero byte is the real
		// content type.
		i := len(out) - 1
		for i >= 0 && out[i] == 0 {
			i--
		}
		if i < 0 {
			return fail("decrypted record is all padding and carries no content type", nil)
		}
		return out[:i], tlsdis.ContentType(out[i]), nil
	}

	// TLS 1.2 AEAD record.
	frag := rec.Fragment
	if len(frag) < s.Suite.RecordIVLen+s.Suite.TagLen {
		return fail(fmt.Sprintf("record is %d bytes, too short for a %d-byte explicit nonce and a %d-byte tag",
			len(frag), s.Suite.RecordIVLen, s.Suite.TagLen), nil)
	}
	var nonce []byte
	if s.Suite.RecordIVLen > 0 {
		nonce = make([]byte, 0, s.Suite.FixedIVLen+s.Suite.RecordIVLen)
		nonce = append(nonce, d.iv...)
		nonce = append(nonce, frag[:s.Suite.RecordIVLen]...)
		frag = frag[s.Suite.RecordIVLen:]
	} else {
		nonce = xorSeq(d.iv, d.seq)
	}
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], d.seq)
	aad[8] = byte(rec.Type)
	aad[9] = byte(rec.Version >> 8)
	aad[10] = byte(rec.Version)
	binary.BigEndian.PutUint16(aad[11:13], uint16(len(frag)-s.Suite.TagLen))

	out, err := d.aead.Open(nil, nonce, frag, aad)
	if err != nil {
		return fail(fmt.Sprintf("AEAD authentication failed (%s, %d-byte fragment)", s.Suite.Name, rec.Length), err)
	}
	return out, rec.Type, nil
}

// xorSeq builds a per-record nonce: the write IV with the 64-bit sequence
// number XORed into its right-hand end (RFC 8446 §5.3, RFC 7905 §2).
func xorSeq(iv []byte, seq uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8 && i < len(nonce); i++ {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * uint(i)))
	}
	return nonce
}

// noteHandshake records a handshake payload and scans the accumulated stream
// for the two messages that change keys.
func (s *Session) noteHandshake(d *dirState, p *Plaintext) {
	if p.Type != tlsdis.ContentHandshake || len(p.Data) == 0 {
		return
	}
	d.hsFrags = append(d.hsFrags, tlsdis.Fragment{
		Data:    append([]byte(nil), p.Data...),
		Record:  p.Record.Index,
		Packets: p.Record.Packets,
	})
	d.hsBuf = append(d.hsBuf, p.Data...)

	// Walk complete messages only. A Finished split across two records is
	// noticed when its second half arrives, which is exactly when the key
	// change takes effect.
	for {
		if len(d.hsBuf)-d.hsScanned < 4 {
			return
		}
		off := d.hsScanned
		typ := tlsdis.HandshakeType(d.hsBuf[off])
		length := int(d.hsBuf[off+1])<<16 | int(d.hsBuf[off+2])<<8 | int(d.hsBuf[off+3])
		if length > tlsdis.MaxHandshakeMessage {
			// Nonsense length: stop scanning rather than loop forever. The
			// handshake parser reports this properly when the caller asks for
			// the messages.
			d.hsScanned = len(d.hsBuf)
			return
		}
		if len(d.hsBuf)-off-4 < length {
			return
		}
		d.hsScanned = off + 4 + length
		switch typ {
		case tlsdis.HandshakeFinished:
			if s.tls13 {
				d.pendingEpochSwitch = true
			}
		case tlsdis.HandshakeKeyUpdate:
			if s.tls13 {
				d.pendingKeyUpdate = true
			}
		}
	}
}

// applyPending performs the key changes a decrypted record announced, AFTER
// that record has been accounted for.
func (s *Session) applyPending(d *dirState) {
	if d.pendingEpochSwitch {
		d.pendingEpochSwitch = false
		if d.epoch == EpochHandshake && d.applicationSecret != nil {
			// Sequence numbers restart from zero with the new keys.
			_ = s.install(d, EpochApplication, d.applicationSecret)
		}
	}
	if d.pendingKeyUpdate {
		d.pendingKeyUpdate = false
		next, err := nextTrafficSecret(s.Suite.Hash, d.secret)
		if err == nil {
			gen := d.generation + 1
			if s.install(d, d.epoch, next) == nil {
				d.generation = gen
			}
		}
	}
}

// Handshake returns the handshake messages recovered for a side so far, parsed
// from the COALESCED fragment stream.
//
// This is the path that yields the client's certificate chain in TLS 1.3, where
// the whole handshake after ServerHello is encrypted — and with it the SunSpec
// role extension that several RBAC test cases turn on.
func (s *Session) Handshake(side Side) (*tlsdis.HandshakeStream, error) {
	return tlsdis.ParseHandshake(s.dirs[side].hsFrags, tlsdis.Options{TLS13: s.tls13})
}

// HandshakeFragments exposes the raw fragments, for callers that want to feed
// them to tlsdis themselves.
func (s *Session) HandshakeFragments(side Side) []tlsdis.Fragment { return s.dirs[side].hsFrags }

// Epoch reports a direction's current key epoch — useful in a report when a
// decryption failed and the question is which keys were in force.
func (s *Session) Epoch(side Side) Epoch { return s.dirs[side].epoch }

// SequenceNumber reports the next record sequence number for a direction.
func (s *Session) SequenceNumber(side Side) uint64 { return s.dirs[side].seq }

// AppData concatenates the application-data payloads of a decrypted direction.
func AppData(ps []Plaintext) []byte {
	var out []byte
	for _, p := range ps {
		if p.Type == tlsdis.ContentApplicationData {
			out = append(out, p.Data...)
		}
	}
	return out
}

// Alerts returns the alerts found among decrypted records. In TLS 1.3 every
// alert after ServerHello is encrypted, so a close_notify — or a fatal
// certificate_required — is only visible here.
func Alerts(ps []Plaintext) []tlsdis.Alert {
	var out []tlsdis.Alert
	for _, p := range ps {
		if p.Type != tlsdis.ContentAlert {
			continue
		}
		for i := 0; i+1 < len(p.Data); i += 2 {
			out = append(out, tlsdis.Alert{
				Level:       p.Data[i],
				Description: p.Data[i+1],
				Record:      p.Record.Index,
				Offset:      p.Record.Offset,
				Packets:     p.Record.Packets,
			})
		}
	}
	return out
}

// ParamsFromHandshake extracts the session parameters from the two directions'
// plaintext handshakes: the client random from the ClientHello, and the server
// random, chosen suite and negotiated version from the ServerHello.
func ParamsFromHandshake(client, server *tlsdis.Direction) (Params, error) {
	var p Params
	if client == nil || client.Handshake == nil {
		return p, fmt.Errorf("tlsdecrypt: no client handshake")
	}
	if server == nil || server.Handshake == nil {
		return p, fmt.Errorf("tlsdecrypt: no server handshake")
	}
	chMsg, ok := client.Handshake.Find(tlsdis.HandshakeClientHello)
	if !ok || chMsg.ClientHello == nil {
		return p, fmt.Errorf("tlsdecrypt: no ClientHello in the client stream")
	}
	shMsg, ok := server.Handshake.Find(tlsdis.HandshakeServerHello)
	if !ok || shMsg.ServerHello == nil {
		return p, fmt.Errorf("tlsdecrypt: no ServerHello in the server stream")
	}
	if shMsg.ServerHello.IsHelloRetryRequest {
		// A HelloRetryRequest is not a negotiated session; the real ServerHello
		// follows it, and using the HRR's parameters would derive keys for a
		// connection that never existed.
		for _, m := range server.Handshake.Messages {
			if m.Type == tlsdis.HandshakeServerHello && m.ServerHello != nil && !m.ServerHello.IsHelloRetryRequest {
				shMsg = m
				break
			}
		}
		if shMsg.ServerHello.IsHelloRetryRequest {
			return p, fmt.Errorf("tlsdecrypt: the server sent only a HelloRetryRequest; no session was established")
		}
	}
	p.ClientRandom = append([]byte(nil), chMsg.ClientHello.Random[:]...)
	p.ServerRandom = append([]byte(nil), shMsg.ServerHello.Random[:]...)
	p.CipherSuite = shMsg.ServerHello.CipherSuite
	p.Version = shMsg.ServerHello.NegotiatedVersion()
	return p, nil
}

// StripPadding removes TLS 1.3 record padding from a payload, returning the
// content and its real type. It is exported for callers holding a decrypted
// inner plaintext from elsewhere.
func StripPadding(inner []byte) ([]byte, tlsdis.ContentType, error) {
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, fmt.Errorf("tlsdecrypt: inner plaintext is all padding")
	}
	return inner[:i], tlsdis.ContentType(inner[i]), nil
}
