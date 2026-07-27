package suitessm

// wire.go is the bridge from "this check opened a connection" to "here are the
// frames that prove what happened on it".
//
// Every citing check in this suite follows the same three steps, and this file
// is all three:
//
//	1. find MY conversation in the run's capture, by the 4-tuple recorded at
//	   dial time — not by port, because a check that opens four probes to :802
//	   has four conversations and picking one by port is picking one at random;
//	2. parse both directions of it with internal/evidence/tlsdis, which is a
//	   SECOND parse of the same bytes the live phase already parsed off the
//	   socket. The two must agree; if they do not, the capture does not evidence
//	   what the check believes it saw, and that disagreement is reported;
//	3. optionally decrypt, when the run exported a key log, so the criteria that
//	   live inside the tunnel can be cited too.
//
// Step 2 is the honesty mechanism. The live phase's observation is what the
// check reasoned from, but the CAPTURE is what a stranger will re-check, so
// every assertion is minted from the capture's parse.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// wireView is one TCP conversation from the capture, parsed as TLS.
type wireView struct {
	// Stream is the reassembled conversation.
	Stream *netdis.Stream
	// ToServer and ToClient are the two reassembled directions.
	ToServer, ToClient *netdis.Direction
	// Client and Server are those directions parsed as TLS.
	Client, Server *tlsdis.Direction
	// ClientErr / ServerErr record parse failures, which are findings rather
	// than reasons to abandon the evidence already recovered.
	ClientErr, ServerErr error
	// Frames is every capture frame this conversation occupied, ascending.
	Frames []int
}

// viewFor locates the conversation with the given 4-tuple among the frames
// attributed to this check and parses it.
//
// The error names what WAS attributed, because "no such stream" with no further
// information is the least actionable message an evidence tool can print.
func viewFor(ev *certify.Evidence, local, remote netip.AddrPort) (*wireView, error) {
	var hit *netdis.Stream
	for _, st := range ev.Streams() {
		a, b := endpointAddr(st.Key.A), endpointAddr(st.Key.B)
		if (a == local && b == remote) || (a == remote && b == local) {
			if hit != nil {
				return nil, fmt.Errorf("suitessm: %s: two attributed conversations match %s <> %s; "+
					"the capture cannot distinguish them", ev.Case.UID, local, remote)
			}
			hit = st
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("suitessm: %s: the capture holds no attributed conversation %s <> %s "+
			"(attributed: %s)", ev.Case.UID, local, remote, strings.Join(ev.Set.Streams, ", "))
	}
	return parseView(hit, local, remote)
}

func parseView(st *netdis.Stream, local, remote netip.AddrPort) (*wireView, error) {
	v := &wireView{Stream: st}
	v.ToServer = st.ByFlow(netdis.FlowKey{Src: toEndpoint(local), Dst: toEndpoint(remote)})
	v.ToClient = st.ByFlow(netdis.FlowKey{Src: toEndpoint(remote), Dst: toEndpoint(local)})
	if v.ToServer == nil || v.ToClient == nil {
		return nil, fmt.Errorf("suitessm: conversation %s does not carry both directions of %s <> %s",
			st.Key, local, remote)
	}
	v.Client, v.ClientErr = tlsdis.ParseDirection(v.ToServer.Bytes.Bytes(), v.ToServer.Bytes)
	v.Server, v.ServerErr = tlsdis.ParseDirection(v.ToClient.Bytes.Bytes(), v.ToClient.Bytes)
	v.Frames = frameSpan(st)
	return v, nil
}

func frameSpan(st *netdis.Stream) []int {
	seen := map[int]bool{}
	for _, d := range st.Dirs {
		if d == nil {
			continue
		}
		for _, f := range d.Bytes.PacketsFor(0, d.Bytes.Len()) {
			seen[f] = true
		}
	}
	out := make([]int, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Ints(out)
	return out
}

func endpointAddr(e netdis.Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr.Unmap(), e.Port)
}

func toEndpoint(a netip.AddrPort) netdis.Endpoint {
	return netdis.Endpoint{Addr: a.Addr(), Port: a.Port()}
}

// ── accessors, each returning the frames that carry the fact ────────────────

// ClientHello returns the parsed hello and the frames it spanned.
func (v *wireView) ClientHello() (*tlsdis.ClientHello, []int) {
	m, ok := find(v.Client, tlsdis.HandshakeClientHello)
	if !ok {
		return nil, nil
	}
	return m.ClientHello, m.Packets
}

// ServerHello returns the parsed hello and the frames it spanned.
func (v *wireView) ServerHello() (*tlsdis.ServerHello, []int) {
	m, ok := find(v.Server, tlsdis.HandshakeServerHello)
	if !ok {
		return nil, nil
	}
	return m.ServerHello, m.Packets
}

// ServerCertificate returns the DUT's cleartext Certificate message.
func (v *wireView) ServerCertificate() (*tlsdis.Certificate, []int) {
	m, ok := find(v.Server, tlsdis.HandshakeCertificate)
	if !ok {
		return nil, nil
	}
	return m.Certificate, m.Packets
}

// ClientCertificate returns the bench's cleartext Certificate message — the one
// carrying the SunSpec role extension the RBAC procedures are about.
func (v *wireView) ClientCertificate() (*tlsdis.Certificate, []int) {
	m, ok := find(v.Client, tlsdis.HandshakeCertificate)
	if !ok {
		return nil, nil
	}
	return m.Certificate, m.Packets
}

// CertificateRequest returns the DUT's cleartext CertificateRequest.
func (v *wireView) CertificateRequest() (*tlsdis.CertificateRequest, []int) {
	m, ok := find(v.Server, tlsdis.HandshakeCertificateRequest)
	if !ok {
		return nil, nil
	}
	return m.CertificateRequest, m.Packets
}

// ServerKeyExchange returns the DUT's cleartext ServerKeyExchange body.
func (v *wireView) ServerKeyExchange() ([]byte, []int) {
	m, ok := find(v.Server, tlsdis.HandshakeServerKeyExchange)
	if !ok {
		return nil, nil
	}
	return m.Body, m.Packets
}

// ServerFlight is the ordered list of cleartext handshake types from the DUT.
func (v *wireView) ServerFlight() []tlsdis.HandshakeType {
	if v.Server == nil || v.Server.Handshake == nil {
		return nil
	}
	return v.Server.Handshake.Types()
}

// ClientFlight is the ordered list of cleartext handshake types from the bench.
func (v *wireView) ClientFlight() []tlsdis.HandshakeType {
	if v.Client == nil || v.Client.Handshake == nil {
		return nil
	}
	return v.Client.Handshake.Types()
}

// ServerFatalAlert returns the DUT's first fatal alert and its frames.
func (v *wireView) ServerFatalAlert() (tlsdis.Alert, bool) {
	if v.Server == nil {
		return tlsdis.Alert{}, false
	}
	return v.Server.FatalAlert()
}

// ServerAppData reports whether the DUT sent any application data, which is the
// "no application_data after the alert" criterion of every negative test.
func (v *wireView) ServerAppData() []int {
	if v.Server == nil {
		return nil
	}
	var out []int
	for _, i := range v.Server.AppData {
		out = append(out, v.Server.Stream.Records[i].Packets...)
	}
	return out
}

func find(d *tlsdis.Direction, t tlsdis.HandshakeType) (tlsdis.HandshakeMessage, bool) {
	if d == nil || d.Handshake == nil {
		return tlsdis.HandshakeMessage{}, false
	}
	return d.Handshake.Find(t)
}

// ── decryption ──────────────────────────────────────────────────────────────

// plaintext is the recovered inside of one conversation.
type plaintext struct {
	// FromClient and FromServer are the decrypted application-data streams.
	FromClient, FromServer []byte
	// ClientRecords and ServerRecords are the decrypted records, so an
	// assertion can cite the exact frames a recovered PDU arrived in.
	ClientRecords, ServerRecords []tlsdecrypt.Plaintext
	// Version and Suite are what the decryption was performed under.
	Version, Suite uint16
}

// framesForServerAppData returns the capture frames carrying the server's
// decrypted application data, in order.
func (p *plaintext) framesForServerAppData() []int {
	return appDataFrames(p.ServerRecords)
}

func appDataFrames(recs []tlsdecrypt.Plaintext) []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range recs {
		if r.Type != tlsdis.ContentApplicationData {
			continue
		}
		for _, f := range r.Frames() {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Ints(out)
	return out
}

// decrypt recovers the conversation's plaintext using the run's key log.
//
// A nil key log, a hello this suite could not parse, or a suite tlsdecrypt does
// not implement all produce an error naming the specific obstacle. Callers turn
// that into a SKIP assertion carrying the reason — never into a PASS on the
// strength of what the check saw locally, because the point of the key log is
// that the READER can repeat the recovery.
func (v *wireView) decrypt(ev *certify.Evidence) (*plaintext, error) {
	if ev.KeyLog == nil {
		return nil, fmt.Errorf("the run exported no TLS key log (-keylog), so the encrypted records in this " +
			"conversation cannot be recovered by anyone reading the bundle")
	}
	ch, _ := v.ClientHello()
	sh, _ := v.ServerHello()
	if ch == nil || sh == nil {
		return nil, fmt.Errorf("the capture does not carry both a ClientHello and a ServerHello for this " +
			"conversation, so the decryption parameters are unknown")
	}
	params := tlsdecrypt.Params{
		Version:      sh.NegotiatedVersion(),
		CipherSuite:  sh.CipherSuite,
		ClientRandom: ch.Random[:],
		ServerRandom: sh.Random[:],
	}
	if !ev.KeyLog.Has(params.ClientRandom) {
		return nil, fmt.Errorf("the key log holds no secrets for client_random %x — this session's keys were "+
			"not exported (the DUT never exports its own; only the bench side does)", params.ClientRandom[:8])
	}
	sess, err := tlsdecrypt.New(params, ev.KeyLog)
	if err != nil {
		return nil, fmt.Errorf("build the decryption session for 0x%04X %s over %s: %w",
			params.CipherSuite, tlsdis.CipherSuiteName(params.CipherSuite),
			tlsdis.VersionName(params.Version), err)
	}
	p := &plaintext{Version: params.Version, Suite: params.CipherSuite}
	p.ClientRecords, err = sess.DecryptAll(tlsdecrypt.Client, v.Client.Stream.Records)
	if err != nil {
		return nil, fmt.Errorf("decrypt the bench→DUT direction: %w", err)
	}
	p.ServerRecords, err = sess.DecryptAll(tlsdecrypt.Server, v.Server.Stream.Records)
	if err != nil {
		return nil, fmt.Errorf("decrypt the DUT→bench direction: %w", err)
	}
	p.FromClient = tlsdecrypt.AppData(p.ClientRecords)
	p.FromServer = tlsdecrypt.AppData(p.ServerRecords)
	return p, nil
}

// findADU locates the first MBAP frame in a decrypted stream whose PDU starts
// with one of the given function codes, and returns it with the frames the
// record(s) carrying it occupied.
//
// It walks the stream frame by frame rather than searching for a byte pattern:
// a Modbus stream is self-delimiting through its Length field, and searching
// for "0x10 somewhere in the plaintext" would happily match a register value.
func findADU(stream []byte, recs []tlsdecrypt.Plaintext, want func(fc byte) bool) ([]byte, []int, bool) {
	off := 0
	for off+8 <= len(stream) {
		v, err := parseMBAP(stream[off:])
		if err != nil || v.Length < 2 {
			return nil, nil, false
		}
		end := off + 6 + int(v.Length)
		if end > len(stream) {
			return nil, nil, false
		}
		if len(v.PDU) > 0 && want(v.PDU[0]) {
			return stream[off:end], framesCovering(recs, off, end), true
		}
		off = end
	}
	return nil, nil, false
}

// framesCovering maps a byte range of the decrypted application-data stream
// back to the capture frames that carried the records it came from.
func framesCovering(recs []tlsdecrypt.Plaintext, start, end int) []int {
	seen := map[int]bool{}
	var out []int
	pos := 0
	for _, r := range recs {
		if r.Type != tlsdis.ContentApplicationData {
			continue
		}
		rs, re := pos, pos+len(r.Data)
		pos = re
		if re <= start || rs >= end {
			continue
		}
		for _, f := range r.Frames() {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Ints(out)
	return out
}
