package suitecsip

// session.go recovers the gateway↔gridsim CSIP session from the run's capture:
// the TLS handshake in the clear, and — when the run exported the bench
// server's secrets — the HTTP/2030.5 transcript inside it, with every message
// traceable to the TLS records and capture frames that carried it.
//
// # Two tiers, recovered separately, reported separately
//
// The handshake tier needs nothing but the pcap. Version, offered and
// negotiated cipher suites, both certificate chains, CertificateRequest and any
// alert are cleartext in TLS 1.2, which is the version CSIP §5.2.1.1 mandates.
// That tier is always populated when the session is in the capture at all.
//
// The transcript tier needs the session's traffic secrets. gridsim is the
// server, so the secrets are the bench's own to export — but if the run had no
// key log, or the log has no entry for this session's client random, the
// transcript is simply not recoverable and Transcript.Undecryptable says which
// of those it was. Nothing here guesses: a check handed a Transcript with
// Decrypted == false must SKIP its payload criteria with that reason.
//
// # Provenance, and why the plaintext is not the citation
//
// A citation has to name bytes a third party can find in the pcap. The
// decrypted plaintext is not in the pcap — the ciphertext is. So every
// recovered HTTP message carries the CIPHERTEXT byte range of the TLS records
// that carried it, plus those records' frame numbers. An assertion then reads:
// "bytes [4181,4712) of 69.0.0.2:41022 > 69.0.0.20:11113, which decrypt under
// the exported key log to `GET /dcap HTTP/1.1 …`". A reviewer with the pcap and
// the key log can re-derive exactly that, and bundle.Verify re-derives the
// digest mechanically.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// MandatoryCipher is TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, the single cipher
// suite IEEE 2030.5 §6.7 / CSIP §5.2.1.1 P9 require of every 2030.5 peer. The
// code point is from the IANA registry (RFC 7251); neither PDF states it, which
// is exactly why it is pinned here as a number rather than matched by name.
const MandatoryCipher uint16 = 0xC0AE

// AggregatorCipher is TLS_RSA_WITH_AES_256_CBC_SHA256, which CSIP P10 requires
// of AGGREGATORS only. The DUT is a direct DER client, so its absence is
// conformant and its presence is merely reported.
const AggregatorCipher uint16 = 0x003D

// TLS12 is the only protocol version CSIP permits (P8). 2030.5-2018 predates
// TLS 1.3 and nothing in either document admits it.
const TLS12 uint16 = 0x0303

// Handshake is everything the cleartext handshake told us about the session.
type Handshake struct {
	ClientHello *tlsdis.ClientHello
	ServerHello *tlsdis.ServerHello
	// ServerChain and ClientChain are the DER certificate chains as sent, leaf
	// first. In TLS 1.2 both are in the clear.
	ServerChain [][]byte
	ClientChain [][]byte
	// CertificateRequest is the server's demand for a client certificate — the
	// wire evidence that mutual authentication was actually required rather
	// than merely offered.
	CertificateRequest *tlsdis.CertificateRequest

	// Frames, per message, for citations.
	ClientHelloFrames []int
	ServerHelloFrames []int
	ServerCertFrames  []int
	ClientCertFrames  []int
	CertReqFrames     []int

	// Alerts seen in the clear, either direction.
	ClientAlerts []tlsdis.Alert
	ServerAlerts []tlsdis.Alert

	// Version and Suite are what the ServerHello settled on; zero when there
	// was no ServerHello (a handshake the server refused).
	Version uint16
	Suite   uint16

	// Complete reports whether both sides reached ChangeCipherSpec, i.e. the
	// handshake finished rather than being abandoned.
	Complete bool
}

// OffersMandatoryCipher reports whether the ClientHello offered 0xC0AE.
func (h *Handshake) OffersMandatoryCipher() bool {
	return h != nil && h.ClientHello != nil && h.ClientHello.OffersSuite(MandatoryCipher)
}

// OfferedSuites renders the ClientHello's suite list for an Observed field.
func (h *Handshake) OfferedSuites() string {
	if h == nil || h.ClientHello == nil {
		return "(no ClientHello)"
	}
	parts := make([]string, 0, len(h.ClientHello.CipherSuites))
	for _, id := range h.ClientHello.CipherSuites {
		parts = append(parts, fmt.Sprintf("0x%04X %s", id, tlsdis.CipherSuiteName(id)))
	}
	return strings.Join(parts, ", ")
}

// Transcript is one recovered CSIP session.
type Transcript struct {
	// Stream is the TCP conversation, and Remote the server endpoint the DUT
	// dialled.
	Stream *netdis.Stream
	Remote netip.AddrPort

	// ClientDir carries DUT→server bytes, ServerDir the reverse. "Client" here
	// is the TLS client, which is the DUT: the gateway dials out.
	ClientDir *netdis.Direction
	ServerDir *netdis.Direction

	// ClientRecords and ServerRecords are the record layers of those two
	// directions.
	ClientRecords *tlsdis.Direction
	ServerRecords *tlsdis.Direction

	Handshake Handshake

	// Decrypted reports whether the application data was recovered.
	Decrypted bool
	// Undecryptable says why it was not, in terms a bundle reader can act on.
	Undecryptable string

	// Requests and Responses are the recovered messages in order; Exchanges
	// pairs them.
	Requests  []*Message
	Responses []*Message
	Exchanges []Exchange

	// AppRecords counts application-data records each way, which is the honest
	// "something was exchanged" statement available without decryption.
	ClientAppRecords int
	ServerAppRecords int
	ClientAppBytes   int
	ServerAppBytes   int

	// Problems collects recovery findings a reader must weigh: a truncated
	// record layer, a decryption failure, a message the parser could not frame.
	Problems []string
}

// GETs returns the exchanges whose request was a GET of path (exact match on
// the path component, query ignored).
func (t *Transcript) GETs(path string) []Exchange {
	return t.Filter(func(e Exchange) bool {
		return e.Req != nil && e.Req.Method == "GET" && e.Req.Path == path
	})
}

// Method returns the exchanges with the given request method.
func (t *Transcript) Method(method string) []Exchange {
	return t.Filter(func(e Exchange) bool { return e.Req != nil && e.Req.Method == method })
}

// Filter returns the exchanges matching a predicate, in order.
func (t *Transcript) Filter(pred func(Exchange) bool) []Exchange {
	var out []Exchange
	for _, e := range t.Exchanges {
		if pred(e) {
			out = append(out, e)
		}
	}
	return out
}

// First returns the first exchange matching a predicate.
func (t *Transcript) First(pred func(Exchange) bool) (Exchange, bool) {
	for _, e := range t.Exchanges {
		if pred(e) {
			return e, true
		}
	}
	return Exchange{}, false
}

// Paths lists the distinct request paths in order of first appearance, which is
// the compact form of "what the DUT walked" that a report line wants.
func (t *Transcript) Paths() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range t.Exchanges {
		if e.Req == nil || seen[e.Req.Path] {
			continue
		}
		seen[e.Req.Path] = true
		out = append(out, e.Req.Path)
	}
	return out
}

// Summary renders the transcript for an assertion's Observed field.
func (t *Transcript) Summary() string {
	if t == nil {
		return "(no session recovered)"
	}
	if !t.Decrypted {
		return fmt.Sprintf("TLS session %s, %d/%d application-data records (%d/%d bytes) DUT→server/server→DUT; "+
			"payload not recovered: %s",
			t.Stream.Key, t.ClientAppRecords, t.ServerAppRecords,
			t.ClientAppBytes, t.ServerAppBytes, t.Undecryptable)
	}
	parts := make([]string, 0, len(t.Exchanges))
	for _, e := range t.Exchanges {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, "; ")
}

// plainSeg maps a range of one direction's decrypted stream back to the TLS
// record that carried it.
type plainSeg struct {
	start, end int
	rec        tlsdis.Record
}

// plainStream is a decrypted direction plus the map back to the ciphertext.
type plainStream struct {
	data []byte
	segs []plainSeg
	// frameTime resolves a capture frame number to its timestamp, so a message
	// can carry the clock a timing criterion must use.
	frameTime func(int) (time.Time, bool)
}

// locate fills a message's ciphertext provenance from its plaintext span.
//
// A message that spans records 7..9 is cited as the byte range covering all
// three records' headers and fragments — not a sub-range of them. That is
// deliberate: a TLS record is the smallest thing in the ciphertext that has a
// meaning, and a citation of half a record would be a citation of nothing a
// reviewer could independently verify.
func (p *plainStream) locate(m *Message) {
	lo, hi := -1, -1
	var frames []int
	var recs []int
	for _, s := range p.segs {
		if s.end <= m.Start || s.start >= m.End {
			// Empty-bodied message: it still lives inside the record whose
			// range contains its start offset.
			if !(m.Start == m.End && s.start <= m.Start && m.Start < s.end) {
				continue
			}
		}
		if lo < 0 || s.rec.Offset < lo {
			lo = s.rec.Offset
		}
		if e := s.rec.End(); e > hi {
			hi = e
		}
		frames = append(frames, s.rec.Packets...)
		recs = append(recs, s.rec.Index)
	}
	if lo < 0 {
		return
	}
	m.CipherStart, m.CipherEnd = lo, hi
	m.Frames = dedupeInts(frames)
	m.Records = dedupeInts(recs)
	if p.frameTime != nil && len(m.Frames) > 0 {
		if ts, ok := p.frameTime(m.Frames[0]); ok {
			m.Time = ts
		}
	}
}

// RecoverSession reconstructs the DUT's CSIP DISCOVERY session with the bench's
// 2030.5 server from the frames attributed to this check.
//
// remote is the server endpoint (host:port) the DUT dialled. The lookup is by
// PORT rather than by full endpoint because the DUT's own address is knowable
// but its ephemeral port is not.
//
// A window routinely catches MORE THAN ONE conversation with that server, and
// demanding exactly one is why this used to recover nothing at all:
//
//   - the gateway's telemetry role POSTs MirrorMeterReadings to the same
//     host:port as the discovery walk, over its own connection;
//   - a server with an idle timeout gives every poll cycle a fresh connection.
//
// So the candidates are enumerated and the discovery session is identified by
// what it CONTAINS — a GET of the discovery root, the one path a 2030.5 client
// may hard-code — rather than by being the only one present. Rejected
// candidates are recorded in Problems, so the choice is auditable instead of a
// silent heuristic.
func RecoverSession(ev *certify.Evidence, remote netip.AddrPort) (*Transcript, error) {
	if !ev.HasFrames() {
		return nil, fmt.Errorf("no capture frames were attributed to this test case")
	}
	streams, err := ev.StreamsOn(remote.Port())
	if err != nil {
		return nil, err
	}

	// Drop conversations this test case does not wholly own.
	//
	// A check may cite only the frames its own connections produced, and the
	// runner enforces that. A short-lived session opened near a window boundary
	// gets SPLIT: some of its frames are attributed here, the rest to the
	// neighbouring case. Recovering a transcript from such a stream produces
	// citations the runner then rejects — "may not cite frame N: it was
	// attributed to <other case>" — which fails the case on a bookkeeping
	// artifact rather than on anything the DUT did.
	//
	// So a straddling conversation is not a candidate at all. It is recorded,
	// because "the session I wanted belonged half to the next test case" is a
	// real and diagnosable condition, not something to pass over in silence.
	var straddled []string
	owned := make([]*netdis.Stream, 0, len(streams))
	for _, st := range streams {
		mine, total := ownedFrames(ev, st)
		switch {
		case total == 0:
			continue
		case mine == total:
			owned = append(owned, st)
		default:
			straddled = append(straddled, fmt.Sprintf("%s (%d of %d frames attributed elsewhere)",
				st.Key, total-mine, total))
		}
	}
	if len(owned) == 0 {
		return nil, fmt.Errorf("none of the %d attributed conversation(s) on port %d is wholly owned by "+
			"this test case, so none can be cited: %s", len(streams), remote.Port(),
			strings.Join(straddled, "; "))
	}
	streams = owned

	type candidate struct {
		t       *Transcript
		err     error
		isDisc  bool
		appRecs int
	}
	cands := make([]candidate, 0, len(streams))
	for _, st := range streams {
		t, terr := recoverFrom(ev, st, remote)
		c := candidate{t: t, err: terr}
		if t != nil {
			c.appRecs = t.ClientAppRecords
			c.isDisc = t.Decrypted && len(t.GETs(DiscoveryRoot)) > 0
		}
		cands = append(cands, c)
	}

	var disc []int
	for i, c := range cands {
		if c.isDisc {
			disc = append(disc, i)
		}
	}
	describe := func(skip int) []string {
		var out []string
		for i, c := range cands {
			if i == skip {
				continue
			}
			switch {
			case c.err != nil:
				out = append(out, fmt.Sprintf("%s (not recovered: %v)", streams[i].Key, c.err))
			case c.t.Decrypted:
				out = append(out, fmt.Sprintf("%s (%d client app record(s), no %s)",
					streams[i].Key, c.appRecs, DiscoveryRoot))
			default:
				out = append(out, fmt.Sprintf("%s (undecryptable: %s)", streams[i].Key, c.t.Undecryptable))
			}
		}
		return out
	}

	switch len(disc) {
	case 1:
		t := cands[disc[0]].t
		if others := describe(disc[0]); len(others) > 0 {
			t.Problems = append(t.Problems, fmt.Sprintf(
				"selected this conversation as the discovery session because it carries GET %s; also "+
					"attributed to this test case: %s", DiscoveryRoot, strings.Join(others, "; ")))
		}
		return t, nil
	case 0:
		// Nothing carried a discovery root. That is a real fact about the
		// window, not licence to pick the biggest and hope — so the fallback
		// is taken, but labelled as unconfirmed.
		if len(cands) == 1 && cands[0].err != nil {
			return nil, cands[0].err
		}
		best, bestRecs := -1, -1
		for i, c := range cands {
			if c.t != nil && c.appRecs > bestRecs {
				best, bestRecs = i, c.appRecs
			}
		}
		if best < 0 {
			return nil, fmt.Errorf("none of the %d attributed conversation(s) on port %d could be recovered: %s",
				len(cands), remote.Port(), strings.Join(describe(-1), "; "))
		}
		t := cands[best].t
		t.Problems = append(t.Problems, fmt.Sprintf(
			"no attributed conversation carried GET %s, so this is NOT confirmed to be the discovery "+
				"session; it is the busiest of %d candidate(s) (%d client app record(s)). Others: %s",
			DiscoveryRoot, len(cands), bestRecs, strings.Join(describe(best), "; ")))
		return t, nil
	default:
		names := make([]string, 0, len(disc))
		for _, i := range disc {
			names = append(names, streams[i].Key.String())
		}
		return nil, fmt.Errorf("%d attributed conversations on port %d each carry GET %s (%s); the "+
			"discovery session is genuinely ambiguous in this window",
			len(disc), remote.Port(), DiscoveryRoot, strings.Join(names, ", "))
	}
}

// ownedFrames reports how many of a conversation's capture frames this test
// case owns, and how many it has in total.
func ownedFrames(ev *certify.Evidence, st *netdis.Stream) (mine, total int) {
	seen := map[int]bool{}
	for _, d := range st.Dirs {
		if d == nil || d.Bytes == nil {
			continue
		}
		for _, f := range d.Bytes.PacketsFor(0, d.Bytes.Len()) {
			if seen[f] {
				continue
			}
			seen[f] = true
			total++
			if ev.Owns(f) {
				mine++
			}
		}
	}
	return mine, total
}

// recoverFrom rebuilds one conversation into a Transcript.
func recoverFrom(ev *certify.Evidence, st *netdis.Stream, remote netip.AddrPort) (*Transcript, error) {
	t := &Transcript{Stream: st, Remote: remote}

	// Which direction is the TLS client? The one that sent the ClientHello.
	// Asking the addresses instead would bake in an assumption about who dialled
	// whom that the capture can answer directly.
	var parsed [2]*tlsdis.Direction
	for i, d := range st.Dirs {
		if d == nil || d.Bytes == nil {
			continue
		}
		pd, perr := tlsdis.ParseDirection(d.Bytes.Bytes(), d.Bytes)
		if pd == nil {
			t.Problems = append(t.Problems, fmt.Sprintf("direction %s did not parse as TLS: %v", d.Flow, perr))
			continue
		}
		if perr != nil {
			t.Problems = append(t.Problems, fmt.Sprintf("direction %s record layer: %v", d.Flow, perr))
		}
		parsed[i] = pd
	}
	ci, si := -1, -1
	for i, pd := range parsed {
		if pd == nil || pd.Handshake == nil {
			continue
		}
		if _, ok := pd.Handshake.Find(tlsdis.HandshakeClientHello); ok {
			ci = i
		}
		if _, ok := pd.Handshake.Find(tlsdis.HandshakeServerHello); ok {
			si = i
		}
	}
	switch {
	case ci < 0 && si < 0:
		return t, fmt.Errorf("neither direction of %s carries a TLS handshake — "+
			"the capture starts after the session was established", st.Key)
	case ci < 0:
		ci = 1 - si
	case si < 0:
		si = 1 - ci
	case ci == si:
		return t, fmt.Errorf("both a ClientHello and a ServerHello appear in the same direction of %s", st.Key)
	}
	t.ClientDir, t.ServerDir = st.Dirs[ci], st.Dirs[si]
	t.ClientRecords, t.ServerRecords = parsed[ci], parsed[si]

	t.Handshake = readHandshake(t.ClientRecords, t.ServerRecords)
	t.countAppData()

	if reason := t.decrypt(ev); reason != "" {
		t.Undecryptable = reason
		return t, nil
	}
	t.Decrypted = true
	return t, nil
}

func (t *Transcript) countAppData() {
	count := func(d *tlsdis.Direction) (int, int) {
		if d == nil || d.Stream == nil {
			return 0, 0
		}
		n, b := 0, 0
		for _, idx := range d.AppData {
			for _, rec := range d.Stream.Records {
				if rec.Index == idx {
					n++
					b += rec.Length
					break
				}
			}
		}
		return n, b
	}
	t.ClientAppRecords, t.ClientAppBytes = count(t.ClientRecords)
	t.ServerAppRecords, t.ServerAppBytes = count(t.ServerRecords)
}

// readHandshake pulls the cleartext handshake facts out of both directions.
func readHandshake(client, server *tlsdis.Direction) Handshake {
	var h Handshake
	if client != nil {
		h.ClientAlerts = client.Alerts
		if client.Handshake != nil {
			if m, ok := client.Handshake.Find(tlsdis.HandshakeClientHello); ok {
				h.ClientHello, h.ClientHelloFrames = m.ClientHello, m.Packets
			}
			if m, ok := client.Handshake.Find(tlsdis.HandshakeCertificate); ok && m.Certificate != nil {
				h.ClientChain, h.ClientCertFrames = m.Certificate.DERChain(), m.Packets
			}
		}
	}
	if server != nil {
		h.ServerAlerts = server.Alerts
		if server.Handshake != nil {
			if m, ok := server.Handshake.Find(tlsdis.HandshakeServerHello); ok && m.ServerHello != nil {
				h.ServerHello, h.ServerHelloFrames = m.ServerHello, m.Packets
				h.Version = m.ServerHello.NegotiatedVersion()
				h.Suite = m.ServerHello.CipherSuite
			}
			if m, ok := server.Handshake.Find(tlsdis.HandshakeCertificate); ok && m.Certificate != nil {
				h.ServerChain, h.ServerCertFrames = m.Certificate.DERChain(), m.Packets
			}
			if m, ok := server.Handshake.Find(tlsdis.HandshakeCertificateRequest); ok {
				h.CertificateRequest, h.CertReqFrames = m.CertificateRequest, m.Packets
			}
		}
	}
	h.Complete = client != nil && server != nil && len(client.CCS) > 0 && len(server.CCS) > 0
	return h
}

// decrypt recovers the application data and parses the HTTP transcript. It
// returns "" on success and otherwise the REASON — not an error — because that
// reason is printed verbatim in the bundle as the explanation for every payload
// criterion this run could not assert. Every branch therefore reads as a
// sentence a reader can act on.
func (t *Transcript) decrypt(ev *certify.Evidence) string {
	if ev.KeyLog == nil {
		return errNoKeyLog
	}
	params, err := tlsdecrypt.ParamsFromHandshake(t.ClientRecords, t.ServerRecords)
	if err != nil {
		return fmt.Sprintf("the session parameters could not be read from the handshake: %v", err)
	}
	if !ev.KeyLog.Has(params.ClientRandom) {
		return fmt.Sprintf("the NSS key log %s holds no secret for this session's client random %x — "+
			"the bench's 2030.5 server (sim/server over sim/tlsserver) does not export TLS secrets, so the "+
			"HTTP/2030.5 payload of a gateway↔gridsim session is not recoverable from the capture",
			ev.KeyLog.Path(), params.ClientRandom[:8])
	}
	sess, err := tlsdecrypt.New(params, ev.KeyLog)
	if err != nil {
		return fmt.Sprintf("the decryption session could not be built: %v", err)
	}
	cp, cerr := sess.DecryptAll(tlsdecrypt.Client, t.ClientRecords.Stream.Records)
	if cerr != nil {
		return fmt.Sprintf("the DUT→server direction did not decrypt: %v", cerr)
	}
	sp, serr := sess.DecryptAll(tlsdecrypt.Server, t.ServerRecords.Stream.Records)
	if serr != nil {
		return fmt.Sprintf("the server→DUT direction did not decrypt: %v", serr)
	}

	frameTime := func(n int) (time.Time, bool) {
		p, ok := ev.Index.Packet(n)
		if !ok {
			return time.Time{}, false
		}
		return p.Time, true
	}
	reqStream := appStream(cp, frameTime)
	respStream := appStream(sp, frameTime)

	reqs, rerr := parseMessages(Request, reqStream, nil)
	if rerr != nil {
		t.Problems = append(t.Problems, rerr.Error())
	}
	methods := make([]string, len(reqs))
	for i, r := range reqs {
		methods[i] = r.Method
	}
	resps, perr := parseMessages(Response, respStream, methods)
	if perr != nil {
		t.Problems = append(t.Problems, perr.Error())
	}
	t.Requests, t.Responses = reqs, resps
	for i, r := range reqs {
		e := Exchange{Req: r}
		if i < len(resps) {
			e.Resp = resps[i]
		}
		t.Exchanges = append(t.Exchanges, e)
	}
	if len(resps) > len(reqs) {
		t.Problems = append(t.Problems, fmt.Sprintf(
			"the server sent %d responses to %d recovered requests; the capture is missing request bytes",
			len(resps), len(reqs)))
	}
	return ""
}

// errNoKeyLog is the standard reason for the commonest tier-2 gap.
const errNoKeyLog = "the run exported no NSS key log (-keylog), so nothing inside the TLS session is recoverable"

// appStream concatenates the application-data plaintexts of one side and
// records where each record's bytes landed.
func appStream(ps []tlsdecrypt.Plaintext, frameTime func(int) (time.Time, bool)) *plainStream {
	s := &plainStream{frameTime: frameTime}
	for _, p := range ps {
		if p.Type != tlsdis.ContentApplicationData || len(p.Data) == 0 {
			continue
		}
		start := len(s.data)
		s.data = append(s.data, p.Data...)
		s.segs = append(s.segs, plainSeg{start: start, end: len(s.data), rec: p.Record})
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].start < s.segs[j].start })
	return s
}

// ByResource returns the exchanges whose RESPONSE body is a 2030.5 resource
// with the given root element name.
//
// This — not the path — is how this suite locates a resource in the transcript.
// IEEE 2030.5 §4.6 makes every URI server-defined: a client must reach
// resources by following hrefs, and a conformance check that looked for
// "GET /edev" would be asserting against one server's URI scheme rather than
// against the standard. Matching on the resource TYPE the server returned is
// both correct and stricter: it catches a server that served a DERProgramList
// at the EndDeviceList's href, which a path match would sail past.
func (t *Transcript) ByResource(name string) []Exchange {
	return t.Filter(func(e Exchange) bool {
		if e.Resp == nil || e.Resp.Status < 200 || e.Resp.Status >= 300 || len(e.Resp.Body) == 0 {
			return false
		}
		doc, err := e.Resp.SEP()
		return err == nil && doc.Local() == name
	})
}

// Resource returns the first exchange whose response is the named resource,
// together with its parsed body.
func (t *Transcript) Resource(name string) (Exchange, *Node, bool) {
	exs := t.ByResource(name)
	if len(exs) == 0 {
		return Exchange{}, nil, false
	}
	doc, err := exs[0].Resp.SEP()
	if err != nil {
		return Exchange{}, nil, false
	}
	return exs[0], doc, true
}

// ResourceNames lists the distinct root element names the server returned, in
// order of first appearance — the compact description of what the DUT actually
// walked, independent of any URI scheme.
func (t *Transcript) ResourceNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range t.Exchanges {
		if e.Resp == nil || len(e.Resp.Body) == 0 {
			continue
		}
		doc, err := e.Resp.SEP()
		if err != nil || seen[doc.Local()] {
			continue
		}
		seen[doc.Local()] = true
		out = append(out, doc.Local())
	}
	return out
}
