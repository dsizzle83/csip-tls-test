package report

// trrlogs.go renders a completed evidence bundle's own capture as the §4
// Detailed Test Logs both specifications require.
//
// # Why this file exists at all
//
// certify's -report mode already derived a Modbus log, and derived it only from
// CLEARTEXT conversations. On this bench that is very nearly nothing: the
// Modbus under test rides mbaps and the CSIP exchanges ride TLS to the gridsim,
// so the emitted archive was empty and the reason was a sentence on the
// console. §4 of both documents is unambiguous about what that archive owes:
//
//	SS-MODBUS-RESULTS-v1.2 §4: "The detailed test logs must contain all Modbus
//	  messages in unencrypted form that were transferred as part of the test."
//	SS-CSIP-RESULTS-v1.1 §4: "The detailed test logs must contain all HTTP(S)
//	  messages in unencrypted form that were transferred as part of the test."
//
// "In unencrypted form" is not a suggestion that the traffic should have been
// plaintext; it is a requirement that the SUBMITTED LOG be readable. The only
// honest way to produce one from a TLS campaign is to decrypt the capture with
// the session secrets the run exported — which is exactly what the bench's
// NSS key log is for, and what internal/evidence/tlsdecrypt already does for
// every other suite. This file reuses that machinery; it parses no TLS itself.
//
// # What it will not do
//
// A session whose secrets are not in the key log is NOT rendered, and NOT
// quietly dropped. §4.1's JSON objects are closed — this package's own parsers
// reject unknown fields, because neither document describes an extension
// element — so there is nowhere INSIDE the log document to record "this
// conversation could not be read". The statement therefore travels beside the
// document, in the notes this function returns, which the generator writes into
// the package README and the readiness report. An archive that is short by four
// sessions with the four named is a gap a reviewer can assess; one that is
// short by four sessions silently is evidence they are right to distrust.

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/bundle"
	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
)

// LogInput is one bundle's contribution to the detailed test logs.
type LogInput struct {
	// Dir is the evidence bundle directory.
	Dir string
	// Bundle is the loaded bundle.
	Bundle *bundle.Bundle
	// ModbusTests and CSIPTests are the procedure identifiers each derived log
	// may name in its `tests` array.
	//
	// They are the ids that carry a reportable verdict, and nothing else. §4.1.1
	// lets one log evidence several procedures, and listing every case in the
	// bundle would be a small forgery: a procedure with no verdict row drove no
	// exchange this log renders.
	ModbusTests []string
	CSIPTests   []string
	// CID is the optional §4.1.1 context id for the CSIP logs. v1.2 of the
	// Modbus document REMOVED cid, so it is never emitted there.
	CID string
}

// DerivedLogs is what could be rendered, and what could not.
type DerivedLogs struct {
	Modbus *ModbusTestLogs
	CSIP   *CSIPTestLogs
	// Notes are one line per fact a reader of the archive needs: how many
	// conversations were rendered, how many were TLS with no usable secret, how
	// many carried neither protocol.
	Notes []string
	// Undecryptable names each TLS conversation whose secrets the key log does
	// not hold. These are the sessions §4 wanted and this run could not supply.
	Undecryptable []string
}

// DeriveTestLogs renders one bundle's capture into the §4 documents.
//
// It never returns an error for a capture it merely could not read: a bundle
// with no capture, an unreadable pcap and a key log that covers nothing are all
// REPORTED, because each is a fact about the submission a reviewer must see,
// and none of them is a reason to abandon the rest of the package.
func DeriveTestLogs(in LogInput) *DerivedLogs {
	out := &DerivedLogs{}
	b := in.Bundle
	if b == nil || b.Files.Capture == "" {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%s declares no capture, so no §4 detailed log can be derived from one", in.Dir))
		return out
	}
	capPath := filepath.Join(in.Dir, filepath.FromSlash(b.Files.Capture))
	fi, err := certify.LoadFrameIndex(capPath)
	if err != nil {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"capture %s could not be read back (%v), so no §4 detailed log was derived from %s",
			b.Files.Capture, err, in.Dir))
		return out
	}

	var kl *keylog.Log
	switch {
	case b.Files.KeyLog == "":
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%s exported no NSS key log, so every TLS conversation in its capture stays ciphertext and "+
				"contributes nothing to the §4 logs, which require the messages in unencrypted form", in.Dir))
	default:
		kl, err = keylog.Open(filepath.Join(in.Dir, filepath.FromSlash(b.Files.KeyLog)))
		if err != nil {
			kl = nil
			out.Notes = append(out.Notes, fmt.Sprintf(
				"the key log %s could not be read (%v), so no TLS conversation in %s was decrypted",
				b.Files.KeyLog, err, in.Dir))
		}
	}

	frames := fi.Frames()
	owners := frameOwners(b)
	modbusReported := set(in.ModbusTests)
	csipReported := set(in.CSIPTests)

	var modbusLogs []ModbusTestLog
	var csipLogs []CSIPTestLog
	rendered := map[string]int{}
	other, unreadable, cited, campaign := 0, 0, 0, 0

	for _, st := range fi.Streams() {
		rec := recoverStream(st, frames, kl)
		if rec.Unreadable != "" {
			unreadable++
			out.Undecryptable = append(out.Undecryptable, rec.Unreadable)
			continue
		}
		switch rec.Kind {
		case streamModbus:
			if len(in.ModbusTests) == 0 {
				continue
			}
			sc := ScanModbusStreams(st, frames, rec.Server, rec.Client, rec.Server2Client)
			if sc.Count(EntryReq)+sc.Count(EntryResp) == 0 {
				continue
			}
			tests, precise := testsFor(owners, entryFrames(sc), modbusReported, in.ModbusTests)
			countScope(precise, &cited, &campaign)
			rendered["Modbus"] += sc.Count(EntryReq) + sc.Count(EntryResp)
			modbusLogs = append(modbusLogs, sc.TestLog(tests...))
		case streamHTTP:
			if len(in.CSIPTests) == 0 {
				continue
			}
			sc := ScanHTTPStreams(rec.Client, rec.Server2Client)
			if len(sc.Messages) == 0 {
				continue
			}
			tests, precise := testsFor(owners, messageFrames(sc), csipReported, in.CSIPTests)
			countScope(precise, &cited, &campaign)
			rendered["HTTP"] += len(sc.Messages)
			csipLogs = append(csipLogs, sc.TestLog(in.CID, tests...))
		default:
			other++
		}
	}

	if len(modbusLogs) > 0 {
		out.Modbus = &ModbusTestLogs{Logs: modbusLogs}
	}
	if len(csipLogs) > 0 {
		out.CSIP = &CSIPTestLogs{CID: in.CID, Logs: csipLogs}
	}

	out.Notes = append(out.Notes, fmt.Sprintf(
		"%s: %d conversation(s) rendered as Modbus log(s) carrying %d message(s); %d rendered as HTTP "+
			"log(s) carrying %d message(s); %d carried neither protocol; %d could not be read",
		in.Dir, len(modbusLogs), rendered["Modbus"], len(csipLogs), rendered["HTTP"], other, unreadable))
	if cited+campaign > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%s: %d of those log(s) name the procedures that CITED a frame of the conversation; %d name "+
				"the campaign's whole reported set, because no assertion in the bundle cites a frame of "+
				"them. §4.1.1's `tests` array is a claim about which procedures a log evidences, and a "+
				"campaign-scoped array is the weaker of the two claims — it is used only where the evidence "+
				"bundle does not support the stronger one", in.Dir, cited, campaign))
	}
	if unreadable > 0 {
		sort.Strings(out.Undecryptable)
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%s: %d conversation(s) are NOT in the §4 logs because this run's key material does not cover "+
				"them. §4 requires ALL messages in unencrypted form, so the emitted archive is incomplete "+
				"by exactly those sessions; every one is named under “Conversations that could not be "+
				"read” below", in.Dir, unreadable))
	}
	return out
}

// frameOwners maps a capture frame to the procedures whose assertions cite it.
//
// This is what makes a §4.1.1 `tests` array a claim rather than a list. The
// obvious implementation names every reported procedure on every log — §4.1.1
// does permit "one or more test procedures … if the log satisfies the
// requirements of more than one" — and it would be a small forgery: a
// conversation that no assertion of BASIC-004 ever cited does not evidence
// BASIC-004, and a reviewer who opened the log to check that procedure would
// find traffic belonging to something else.
//
// The bundle already holds the answer. Every assertion carries the frames it was
// derived from, so a conversation's frames intersected with those citations
// gives exactly the procedures this conversation is evidence for.
func frameOwners(b *bundle.Bundle) map[int][]string {
	owners := map[int][]string{}
	for _, c := range b.Cases {
		id := TestIDOf(c.ID)
		for _, a := range c.Assertions {
			for _, f := range a.Frames {
				if !containsStr(owners[f], id) {
					owners[f] = append(owners[f], id)
				}
			}
		}
	}
	return owners
}

// testsFor returns the §4.1.1 `tests` array for one conversation, and whether
// it is the PRECISE claim or the campaign-scoped fallback.
//
// The precise claim — the procedures whose own assertions cite a frame of this
// conversation — is used whenever the bundle supports it. When it does not, the
// array is the campaign's whole reported set. That fallback is weaker but it is
// still true: the archive is the campaign's traffic and these are the campaign's
// reported procedures. It is NOT a licence to drop the conversation, because §4
// asks for ALL the messages and an archive missing the session a reviewer wants
// fails the requirement that actually matters. Which logs are which is counted
// in the derivation notes rather than left for a reader to infer.
func testsFor(owners map[int][]string, frames []int, reported map[string]bool, all []string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	for _, f := range frames {
		for _, id := range owners[f] {
			if !reported[id] || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return all, false
	}
	sort.Strings(out)
	return out, true
}

func countScope(precise bool, cited, campaign *int) {
	if precise {
		*cited++
		return
	}
	*campaign++
}

func entryFrames(sc *ModbusScan) []int {
	var out []int
	for _, e := range sc.Entries {
		out = append(out, e.Frames...)
	}
	return out
}

func messageFrames(sc *HTTPScan) []int {
	var out []int
	for _, m := range sc.Messages {
		out = append(out, m.Frames...)
	}
	return out
}

func set(v []string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[s] = true
	}
	return m
}

// streamKind classifies what a conversation carried, once decrypted.
type streamKind int

const (
	streamOther streamKind = iota
	streamModbus
	streamHTTP
)

// recovered is one conversation's two directions, after decryption if it needed
// any, oriented so Client is the direction addressed TO the server.
//
// Unreadable is set — and Kind left at streamOther — when the conversation
// carried TLS this run has no secret for. It is deliberately distinct from
// "carried neither protocol": one is a gap in the evidence, the other is
// traffic that was never in scope, and a submission that conflated them would
// hide the first behind the second.
type recovered struct {
	Kind          streamKind
	Client        ByteStream
	Server2Client ByteStream
	Server        netip.AddrPort
	Unreadable    string
}

// recoverStream returns a conversation's plaintext and what protocol it speaks.
//
// Orientation comes from the SYN when one was captured — the endpoint a SYN is
// addressed to IS the server, which is a fact rather than a heuristic. Without
// a SYN the classifier falls back to whichever orientation the payload parses
// as, and says nothing it cannot support: a conversation it cannot orient is
// reported as neither protocol rather than logged the wrong way round.
func recoverStream(st *netdis.Stream, frames []*netdis.Frame, kl *keylog.Log) recovered {
	unreadable := func(format string, a ...any) recovered {
		return recovered{Unreadable: fmt.Sprintf("`%s` — %s", st.Key, fmt.Sprintf(format, a...))}
	}
	if len(st.Dirs) < 2 || st.Dirs[0] == nil || st.Dirs[1] == nil {
		return recovered{}
	}
	client, srv := orient(st, frames)
	if client == nil || srv == nil {
		return recovered{}
	}
	server := endpointAddrPort(client.Flow.Dst)

	if !directionIsTLS(client) && !directionIsTLS(srv) {
		r := recovered{
			Client:        DirectionStream(client, frames),
			Server2Client: DirectionStream(srv, frames),
			Server:        server,
		}
		r.Kind = classify(r.Client.Data)
		return r
	}

	if kl == nil {
		return unreadable("carried TLS records and the run holds no usable key log")
	}
	cd, err := tlsdis.ParseDirection(client.Bytes.Bytes(), client.Bytes)
	if err != nil {
		return unreadable("client TLS records did not parse: %v", err)
	}
	sd, err := tlsdis.ParseDirection(srv.Bytes.Bytes(), srv.Bytes)
	if err != nil {
		return unreadable("server TLS records did not parse: %v", err)
	}
	params, err := tlsdecrypt.ParamsFromHandshake(cd, sd)
	if err != nil {
		return unreadable("%v", err)
	}
	sess, err := tlsdecrypt.New(params, kl)
	if err != nil {
		return unreadable("%v", err)
	}
	byIndex := frameIndex(frames)
	cbs, err := decryptedStream(client.Flow.String(), sess, tlsdecrypt.Client, cd, byIndex)
	if err != nil {
		return unreadable("decrypting the client direction: %v", err)
	}
	sbs, err := decryptedStream(srv.Flow.String(), sess, tlsdecrypt.Server, sd, byIndex)
	if err != nil {
		return unreadable("decrypting the server direction: %v", err)
	}
	return recovered{
		Kind: classify(cbs.Data), Client: cbs, Server2Client: sbs, Server: server,
	}
}

// orient returns the client-to-server and server-to-client directions.
func orient(st *netdis.Stream, frames []*netdis.Frame) (client, srv *netdis.Direction) {
	syn, _ := controlFrames(st, frames)
	if syn != nil {
		if fl, ok := syn.Flow(); ok {
			for _, d := range st.Dirs {
				if d == nil {
					continue
				}
				if d.Flow == fl {
					client = d
				} else {
					srv = d
				}
			}
			if client != nil && srv != nil {
				return client, srv
			}
		}
	}
	// No SYN: prefer the direction whose destination port is the lower of the
	// two, which is the convention every service on this bench follows. It is a
	// guess, and it is only ever used to decide which half is labelled `req`;
	// a wrong guess produces entries that fail to frame, not entries that lie.
	a, b := st.Dirs[0], st.Dirs[1]
	if a.Flow.Dst.Port <= b.Flow.Dst.Port {
		return a, b
	}
	return b, a
}

// directionIsTLS reports whether a direction opens with a TLS record header.
func directionIsTLS(d *netdis.Direction) bool {
	if d == nil || d.Bytes == nil {
		return false
	}
	b := d.Bytes.Bytes()
	return len(b) >= 3 && b[0] >= 0x14 && b[0] <= 0x17 && b[1] == 0x03
}

// classify decides what a plaintext client direction speaks.
//
// HTTP is recognised by its request line, Modbus by an MBAP header whose
// Protocol ID is zero and whose Length describes the bytes that follow. Neither
// test can be fooled by the other: an HTTP method is not a valid two-byte
// transaction id followed by 0x0000.
func classify(data []byte) streamKind {
	if len(data) == 0 {
		return streamOther
	}
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(string(data), m) {
			return streamHTTP
		}
	}
	if len(data) >= 8 && be16(data[2:4]) == 0 {
		length := int(be16(data[4:6]))
		if length >= 2 && 6+length <= len(data) {
			return streamModbus
		}
	}
	return streamOther
}

// decryptedStream turns one side of a TLS session into a ByteStream whose
// offsets map back to the capture frames the ciphertext arrived in.
//
// The mapping is the whole point. A log entry derived from decrypted bytes with
// no route back to a frame would be an assertion about a plaintext nobody else
// can locate; with it, a reviewer holding the pcap and the key log lands on the
// exact record.
func decryptedStream(label string, sess *tlsdecrypt.Session, side tlsdecrypt.Side,
	dir *tlsdis.Direction, byIndex map[int]*netdis.Frame) (ByteStream, error) {
	type seg struct {
		start, end int
		frames     []int
	}
	var data []byte
	var segs []seg
	for _, rec := range dir.Stream.Records {
		p, err := sess.Decrypt(side, rec)
		if err != nil {
			return ByteStream{}, err
		}
		if p.Type != tlsdis.ContentApplicationData || len(p.Data) == 0 {
			continue
		}
		start := len(data)
		data = append(data, p.Data...)
		segs = append(segs, seg{start: start, end: len(data), frames: append([]int(nil), p.Record.Packets...)})
	}
	find := func(off int) (seg, bool) {
		for _, s := range segs {
			if off >= s.start && off < s.end {
				return s, true
			}
		}
		return seg{}, false
	}
	return ByteStream{
		Label: label,
		Data:  data,
		At: func(off int) (int, time.Time, bool) {
			s, ok := find(off)
			if !ok || len(s.frames) == 0 {
				return 0, time.Time{}, false
			}
			f, ok := byIndex[s.frames[0]]
			if !ok {
				return 0, time.Time{}, false
			}
			return f.Index, f.Time, true
		},
		Frames: func(start, end int) []int {
			seen := map[int]bool{}
			var out []int
			for _, s := range segs {
				if s.end <= start || s.start >= end {
					continue
				}
				for _, f := range s.frames {
					if !seen[f] {
						seen[f] = true
						out = append(out, f)
					}
				}
			}
			sort.Ints(out)
			return out
		},
	}, nil
}

// MergeModbusLogs concatenates several bundles' Modbus logs into the one
// archivable §4.1.3 Test Logs Object a submission carries.
func MergeModbusLogs(parts ...*ModbusTestLogs) *ModbusTestLogs {
	out := &ModbusTestLogs{}
	for _, p := range parts {
		if p == nil {
			continue
		}
		out.Logs = append(out.Logs, p.Logs...)
	}
	if len(out.Logs) == 0 {
		return nil
	}
	return out
}

// MergeCSIPLogs is the CSIP counterpart. The context id is taken from the first
// part that carries one: §4.1.1's cid associates separately-archived logs, and
// two different ids in one document would defeat that.
func MergeCSIPLogs(parts ...*CSIPTestLogs) *CSIPTestLogs {
	out := &CSIPTestLogs{}
	for _, p := range parts {
		if p == nil {
			continue
		}
		if out.CID == "" {
			out.CID = p.CID
		}
		out.Logs = append(out.Logs, p.Logs...)
	}
	if len(out.Logs) == 0 {
		return nil
	}
	return out
}
