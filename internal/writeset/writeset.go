// Package writeset extracts the SOUTHBOUND REGISTER WRITE SET from a captured
// leg, post hoc, and attributes it to a named control.
//
// # The claim it exists to make checkable
//
// PC-001's supersession claims are of the form "a supersession over
// byte-identical curves writes ONLY the admitted axes". Nothing on this bench
// could produce the artefact that settles one. mbapref.FromCapture builds a
// FUZZ CORPUS — it deduplicates frames by content hash and drops timestamps,
// because a corpus wants one copy of each distinct shape and a timeline wants
// every occurrence in order — and it is library-only besides. The reconciler's
// own logs say what it decided; they are not the wire, and a claim about what a
// gateway WROTE that rests on the gateway's account of its own writes is not
// evidence about the gateway.
//
// So the write set had to be read off the capture the bundle already carries.
// This package does that, and the certify -writes mode prints it.
//
// # Post hoc, on a bundle, offline
//
// Everything here runs against `capture/*.pcapng` (+ `capture/*.keylog`) in an
// existing evidence bundle. It never touches the bench, never needs the DUT, and
// can run while a battery is still going — which is the point: the operator
// captures the supersession windows tonight and extracts them afterwards.
//
// # What is derived from the capture, and what is asserted
//
// Two things are DERIVED rather than configured, because a tool that had to be
// told them could be told them wrongly:
//
//   - THE MODEL CHAIN. The gateway's own SunSpec discovery reads are in the
//     capture: a two-register read whose response is (modelID, length) is a
//     model header, and the sequence of them IS the device's chain. So a write's
//     owning model is resolved from the same capture the write is in, and a
//     write that lands outside every discovered block is reported as
//     model=unknown rather than guessed at.
//   - THE mRID's WINDOW. Given -mrid, the window is [first frame whose
//     application bytes contain that mRID, last such frame + settle]. It is
//     stated in the output in those words, because "attributed" is a claim about
//     a rule and a reader must be able to disagree with the rule.
//
// Nothing here interprets a value. It prints addresses, counts, raw register
// values, frame numbers and timestamps; what those mean against
// model_7NN.json is the reader's to check, and that is deliberate — this tool's
// job is to make the wire legible, not to grade it.
package writeset

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"csip-tls-test/internal/evidence/keylog"
	"csip-tls-test/internal/evidence/netdis"
	"csip-tls-test/internal/evidence/pcapng"
	"csip-tls-test/internal/evidence/tlsdecrypt"
	"csip-tls-test/internal/evidence/tlsdis"
	"csip-tls-test/internal/mbapref"
)

// DefaultPlainPorts are the plaintext Modbus/TCP ports this bench uses.
// mbapref.DefaultModbusPorts is the same list and is the reason this one is
// stated rather than invented.
var DefaultPlainPorts = mbapref.DefaultModbusPorts

// DefaultTLSPorts are the SOUTHBOUND ports whose Modbus rides inside TLS. 802 is
// Secure SunSpec Modbus; 8021 is where the unprivileged mbapsdev binds. Streams
// on these are decrypted AND decoded as Modbus.
var DefaultTLSPorts = []uint16{802, 8021}

// DefaultNorthboundTLSPorts are the ports the CSIP traffic rides on. They are
// decrypted but NOT decoded as Modbus: nothing writes registers over them, and
// the reason to decrypt them is that THE mRID LIVES THERE.
//
// GATE FINDING D4. Only the southbound ports were decrypted, so a northbound
// leg on 443 was searched as CIPHERTEXT — the mRID was never going to be found
// — and the "no usable key log" error implied a key log would fix it. It would
// not have: 443 was in neither list, so no key log could have been applied to
// it. The mRID search is the whole basis of attribution, so the port it lives
// on has to be decrypted.
//
// 11113 is where this bench's gridsim listens (docs/BENCH.md §b); 443 and 8443
// are the ordinary HTTPS pair a different deployment would use.
var DefaultNorthboundTLSPorts = []uint16{443, 8443, 11113}

// DefaultSettle is how far past the last mention of an mRID a write is still
// attributed to it.
//
// A control's registers are written AFTER the DUT has fetched and decided on it,
// so a window that ended at the last mention would exclude the very writes the
// claim is about. Ten seconds spans the reconciler's own ~10 s tick (the same
// number oracleSettleWindow records) with margin, and it is printed in the
// output so a reader can see what was included on this ground rather than on
// the mRID's own appearance.
const DefaultSettle = 10 * time.Second

// Options configures an extraction.
type Options struct {
	// Path is an evidence bundle directory OR a capture file. A directory is
	// resolved to capture/*.pcapng + capture/*.keylog.
	Path string
	// KeyLogPath overrides the key log discovered beside the capture.
	KeyLogPath string
	// PlainPorts / TLSPorts override the southbound port sets; NorthboundTLSPorts
	// overrides the ports decrypted for the mRID search only.
	PlainPorts, TLSPorts, NorthboundTLSPorts []uint16
	// MRID, when set, restricts the report to writes attributed to that control.
	MRID string
	// Settle extends the mRID window past EACH mention. Zero uses DefaultSettle.
	Settle time.Duration
	// UntilMRID cuts the window at the first mention of a superseding control.
	//
	// It is the honest cut for a supersession pair, and the caller knows the
	// pair: two controls delivered in one list document cannot be told apart by
	// time (see coResident), so the boundary has to come from the claim being
	// made rather than from the capture.
	UntilMRID string
}

// Write is one register-writing Modbus request, as it appeared on the wire.
type Write struct {
	Time   time.Time
	Frame  int    // 1-based capture frame index that delivered the ADU's first byte
	Flow   string // "src > dst"
	TLS    bool   // recovered from inside TLS
	Unit   uint8
	FC     uint8
	Addr   uint16
	Count  uint16
	Values []uint16

	// Model / ModelBase are the SunSpec block this address falls in, derived
	// from the capture's own header reads. Model 0 means no discovered block
	// contains it.
	Model     uint16
	ModelBase uint16
}

// Offset is the write's register offset within its model's data block, or -1
// when the model is unknown.
func (w Write) Offset() int {
	if w.Model == 0 {
		return -1
	}
	return int(w.Addr) - int(w.ModelBase)
}

// Axis is the grouping key: the model that owns the address, or "unknown".
func (w Write) Axis() string {
	if w.Model == 0 {
		return "unknown"
	}
	return fmt.Sprintf("M%d", w.Model)
}

// Block is one SunSpec model discovered in the capture's own header reads.
type Block struct {
	Model  uint16
	Base   uint16 // first DATA register (past the id/length pair)
	Length uint16 // declared L
	Frame  int    // the frame whose response declared it
}

// Contains reports whether addr falls in this block's data region.
func (b Block) Contains(addr uint16) bool {
	return addr >= b.Base && int(addr) < int(b.Base)+int(b.Length)
}

// end is the first register past this block.
func (b Block) end() int { return int(b.Base) + int(b.Length) }

// overlaps reports whether two blocks claim any register in common.
func (b Block) overlaps(o Block) bool {
	return int(b.Base) < o.end() && int(o.Base) < b.end()
}

// Mention is one appearance of an mRID in the capture.
type Mention struct {
	Frame int
	Time  time.Time
}

// Window is what an mRID's writes were attributed over.
//
// GATE FINDING D2. This used to be ONE interval, [first mention .. last mention
// + settle], and on a polled protocol that is the wrong shape entirely: a
// DERControl stays in /derp/0/derc until it expires or is superseded, and the
// DUT re-fetches the list every pollRate — so "first to last mention" is THE
// WHOLE TIME THE CONTROL WAS SERVED, not the time it acted. A retained
// re-delivery ten minutes on pulled an unrelated write in with excluded=0: the
// same wrong answer the fixture's ninth frame exists to prevent, reached by
// another route.
//
// The window is now the UNION OF PER-MENTION INTERVALS: a write is attributed
// when it falls within settle of SOME mention, not merely between the first and
// the last. A ten-minute gap between two mentions no longer swallows the ten
// minutes.
type Window struct {
	Mentions []Mention
	Settle   time.Duration

	// Gaps are the inter-mention intervals longer than Settle — the places
	// where the old span-shaped rule would have attributed writes that this one
	// excludes. Printed, because a reader deciding whether to trust an
	// extraction needs to see that the control's mentions were DISCONTINUOUS.
	Gaps []Gap

	// Bound, when set, truncates the window: no write at or after it is
	// attributed. It is the supersession cut — see Options.UntilMRID.
	Bound     *time.Time
	BoundMRID string
}

// Gap is a discontinuity between consecutive mentions.
type Gap struct {
	AfterFrame, BeforeFrame int
	Duration                time.Duration
}

// First returns the earliest mention time.
func (w *Window) First() time.Time {
	if len(w.Mentions) == 0 {
		return time.Time{}
	}
	return w.Mentions[0].Time
}

// Last returns the latest mention time.
func (w *Window) Last() time.Time {
	if len(w.Mentions) == 0 {
		return time.Time{}
	}
	return w.Mentions[len(w.Mentions)-1].Time
}

// covers reports whether t falls within settle of some mention, and before any
// supersession bound.
func (w *Window) covers(t time.Time) bool {
	if w.Bound != nil && !t.Before(*w.Bound) {
		return false
	}
	for _, m := range w.Mentions {
		if !t.Before(m.Time) && !t.After(m.Time.Add(w.Settle)) {
			return true
		}
	}
	return false
}

// Result is one extraction.
type Result struct {
	Capture     string
	KeyLog      string
	Chain       []Block
	Writes      []Write // every write found, in wire order
	MRID        string
	Window      *Window // nil when no mRID was given
	Excluded    int     // writes outside the window, when an mRID was given
	CoResidents []CoResident
	Notes       []string
}

// Confounded reports whether anything in this extraction makes its attribution
// unsafe to cite without qualification: another control in the same document,
// or another control's mentions inside this one's window.
//
// It is the field the report's banner is driven from, so a clean extraction and
// a confounded one are visually distinct at a glance rather than only to a
// reader who compares mention lists.
func (r *Result) Confounded() bool {
	for _, c := range r.CoResidents {
		if len(c.SharedFrames) > 0 || c.MentionsInWindow > 0 {
			return true
		}
	}
	return false
}

// Attributed returns the writes inside the mRID window, or all writes when no
// mRID was given.
func (r *Result) Attributed() []Write {
	if r.Window == nil {
		return r.Writes
	}
	var out []Write
	for _, w := range r.Writes {
		if r.Window.covers(w.Time) {
			out = append(out, w)
		}
	}
	return out
}

// Extract reads the capture and returns its write set.
func Extract(opts Options) (*Result, error) {
	capPath, klPath, err := resolve(opts)
	if err != nil {
		return nil, err
	}
	res := &Result{Capture: capPath, KeyLog: klPath, MRID: opts.MRID}

	pkts, err := pcapng.ReadFile(capPath)
	if err != nil {
		return nil, fmt.Errorf("writeset: read capture %s: %w", capPath, err)
	}
	frameTime := make(map[int]time.Time, len(pkts))
	for _, p := range pkts {
		frameTime[p.Index] = p.Time
	}

	asm := netdis.NewAssembler()
	for _, p := range pkts {
		// A packet the dissector cannot make sense of costs one frame, not the
		// extraction — the same rule mbapref.FromCapture applies for the same
		// reason.
		_, _ = asm.AddPacket(p)
	}

	var kl *keylog.Log
	if klPath != "" {
		if kl, err = keylog.Open(klPath); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"key log %s could not be read (%v) — TLS legs are ciphertext in this report", klPath, err))
			kl = nil
		}
	}

	plain := opts.PlainPorts
	if plain == nil {
		plain = DefaultPlainPorts
	}
	tlsPorts := opts.TLSPorts
	if tlsPorts == nil {
		tlsPorts = DefaultTLSPorts
	}
	northPorts := opts.NorthboundTLSPorts
	if northPorts == nil {
		northPorts = DefaultNorthboundTLSPorts
	}

	// Every application-layer byte stream in the capture, paired into Modbus
	// conversations (which the chain derivation needs, since the request
	// carries the address and the response carries what is at it).
	convs, streams := collectStreams(asm, plain, tlsPorts, northPorts, kl, res)

	for _, c := range convs {
		res.Chain = append(res.Chain, discoverBlocks(c, frameTime)...)
	}
	res.Chain = dedupeBlocks(res.Chain)
	var droppedOverlaps int
	res.Chain, droppedOverlaps = rejectOverlaps(res.Chain)
	if droppedOverlaps > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%d discovered block(s) overlapped another and were ALL dropped — an overlap proves at least "+
				"one is a phantom and there is no honest way to choose, so the writes they would have "+
				"labelled report model=unknown with their address instead", droppedOverlaps))
	}

	for _, c := range convs {
		if c.toDevice == nil {
			continue
		}
		res.Writes = append(res.Writes, c.toDevice.writes(frameTime, res.Chain)...)
	}
	sort.SliceStable(res.Writes, func(i, j int) bool {
		if res.Writes[i].Time.Equal(res.Writes[j].Time) {
			return res.Writes[i].Frame < res.Writes[j].Frame
		}
		return res.Writes[i].Time.Before(res.Writes[j].Time)
	})

	if opts.MRID != "" {
		settle := opts.Settle
		if settle == 0 {
			settle = DefaultSettle
		}
		w, err := findWindow(streams, frameTime, opts.MRID, opts.UntilMRID, settle)
		if err != nil {
			return nil, err
		}
		if w == nil {
			return nil, fmt.Errorf("writeset: the mRID %q does not appear anywhere in %s — "+
				"either the control was not carried on this leg's capture, or the traffic carrying it "+
				"is TLS and no usable key log was supplied", opts.MRID, capPath)
		}
		res.Window = w
		res.CoResidents = coResident(streams, frameTime, opts.MRID, w)
		res.Excluded = len(res.Writes) - len(res.Attributed())
	}
	return res, nil
}

// resolve turns a bundle directory or capture path into the two files.
func resolve(opts Options) (capPath, klPath string, err error) {
	st, err := os.Stat(opts.Path)
	if err != nil {
		return "", "", fmt.Errorf("writeset: %w", err)
	}
	if !st.IsDir() {
		return opts.Path, opts.KeyLogPath, nil
	}
	dir := filepath.Join(opts.Path, "capture")
	if _, err := os.Stat(dir); err != nil {
		// A capture file may also sit directly in the directory.
		dir = opts.Path
	}
	caps, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if len(caps) == 0 {
		caps, _ = filepath.Glob(filepath.Join(dir, "*.pcap"))
	}
	if len(caps) == 0 {
		return "", "", fmt.Errorf("writeset: %s holds no capture (looked for %s/*.pcapng)", opts.Path, dir)
	}
	sort.Strings(caps)
	capPath = caps[0]
	if opts.KeyLogPath != "" {
		return capPath, opts.KeyLogPath, nil
	}
	kls, _ := filepath.Glob(filepath.Join(dir, "*.keylog"))
	sort.Strings(kls)
	if len(kls) > 0 {
		klPath = kls[0]
	}
	return capPath, klPath, nil
}

// appStream is one direction's application bytes with the offset->frame map
// that dates them.
type appStream struct {
	flow     string
	bytes    []byte
	sb       *netdis.StreamBytes
	tls      bool
	modbus   bool
	toDevice bool
	// recFrames maps a decrypted record's byte offset to its frame, for TLS
	// streams where sb offsets are ciphertext offsets and cannot be used.
	recFrames []recSpan
}

// recSpan maps a run of decrypted bytes back to the frame that carried the
// record they came from.
type recSpan struct {
	end   int // exclusive end offset in the decrypted stream
	frame int
}

// frameAt maps a decrypted-stream offset to a capture frame.
func (a *appStream) frameAt(off int) int {
	if !a.tls {
		if a.sb == nil {
			return 0
		}
		return a.sb.OffsetToPacket(off)
	}
	for _, s := range a.recFrames {
		if off < s.end {
			return s.frame
		}
	}
	return 0
}

// collectStreams gathers the Modbus conversations and, separately, every
// readable application stream (which the mRID search scans).
func collectStreams(asm *netdis.Assembler, plain, tlsPorts, northPorts []uint16, kl *keylog.Log, res *Result) ([]*conv, []*appStream) {
	var convs []*conv
	var out []*appStream
	seen := map[string]bool{}

	// modbus says whether this port's plaintext is decoded as Modbus. A
	// northbound port is decrypted for the mRID search and never decoded: a
	// DERControlList is not an MBAP stream, and running the ADU walker over one
	// would resynchronise its way into inventing frames.
	add := func(port uint16, isTLS, modbus bool) {
		for _, s := range asm.FindPort(port) {
			c := &conv{}
			for _, d := range s.Dirs {
				if d == nil || d.Bytes == nil || d.Bytes.Len() == 0 {
					continue
				}
				key := fmt.Sprintf("%s/%d", d.Flow.String(), d.Gen)
				if seen[key] {
					continue
				}
				seen[key] = true
				toDevice := d.Flow.Dst.Port == port
				as := &appStream{
					flow: d.Flow.String(), sb: d.Bytes, tls: isTLS,
					modbus: modbus, toDevice: toDevice,
				}
				switch {
				case !isTLS:
					as.bytes = d.Bytes.Bytes()
				case kl == nil, decryptInto(as, s, d, kl) != nil:
					// A NORTHBOUND port is only a GUESS about where TLS is: the
					// list names the ports CSIP usually rides, and a bench that
					// serves it in the clear (or a capture whose handshake is
					// not in the window) must still be searchable for the mRID.
					// So the plaintext is kept and the search runs over it —
					// which finds nothing if the bytes really are ciphertext,
					// and that is the honest outcome rather than a dropped
					// stream nobody is told about.
					//
					// A SOUTHBOUND port is different: undecryptable there means
					// its writes are genuinely unreadable, and pretending the
					// ciphertext is an MBAP stream would have the ADU walker
					// resynchronising its way into inventing frames.
					if modbus {
						res.Notes = append(res.Notes, fmt.Sprintf(
							"%s is TLS and could not be decrypted (no usable key log) — its writes are "+
								"NOT in this report", as.flow))
						continue
					}
					as.tls = false
					as.bytes = d.Bytes.Bytes()
					res.Notes = append(res.Notes, fmt.Sprintf(
						"%s was not decrypted; it is searched for the mRID as raw bytes, which finds "+
							"nothing if it is genuinely ciphertext", as.flow))
				}
				out = append(out, as)
				if !modbus {
					continue
				}
				if toDevice {
					c.toDevice = as
				} else {
					c.fromDevice = as
				}
			}
			if c.toDevice != nil || c.fromDevice != nil {
				convs = append(convs, c)
			}
		}
	}
	for _, p := range plain {
		add(p, false, true)
	}
	for _, p := range tlsPorts {
		add(p, true, true)
	}
	for _, p := range northPorts {
		add(p, true, false)
	}

	// Every OTHER stream, plaintext only, so an mRID carried on a northbound
	// leg this tool does not decode can still be FOUND. They are not marked
	// modbus, so nothing is decoded as a write from them.
	for _, s := range asm.Streams() {
		for _, d := range s.Dirs {
			if d == nil || d.Bytes == nil || d.Bytes.Len() == 0 {
				continue
			}
			key := fmt.Sprintf("%s/%d", d.Flow.String(), d.Gen)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, &appStream{flow: d.Flow.String(), bytes: d.Bytes.Bytes(), sb: d.Bytes})
		}
	}
	return convs, out
}

// decryptInto recovers one TLS direction's plaintext, recording which frame
// carried each record so a write can still be dated.
func decryptInto(as *appStream, s *netdis.Stream, d *netdis.Direction, kl *keylog.Log) error {
	var client, server *netdis.Direction
	for _, x := range s.Dirs {
		if x == nil || x.Bytes == nil {
			continue
		}
		if x.Flow == d.Flow {
			continue
		}
		server = x
	}
	client = d
	if server == nil {
		return fmt.Errorf("only one direction of the TLS conversation is in the capture")
	}
	// ParamsFromHandshake wants the two halves in client/server order; which of
	// the pair is the client is decided by who dialled the port.
	cDir, sDir := client, server
	if !isToPort(client) {
		cDir, sDir = server, client
	}
	cParsed, err := tlsdis.ParseDirection(cDir.Bytes.Bytes(), cDir.Bytes)
	if err != nil {
		return fmt.Errorf("parse client TLS records: %w", err)
	}
	sParsed, err := tlsdis.ParseDirection(sDir.Bytes.Bytes(), sDir.Bytes)
	if err != nil {
		return fmt.Errorf("parse server TLS records: %w", err)
	}
	params, err := tlsdecrypt.ParamsFromHandshake(cParsed, sParsed)
	if err != nil {
		return err
	}
	sess, err := tlsdecrypt.New(params, kl)
	if err != nil {
		return err
	}
	side, parsed := tlsdecrypt.Client, cParsed
	if d.Flow != cDir.Flow {
		side, parsed = tlsdecrypt.Server, sParsed
	}
	var buf []byte
	for _, rec := range parsed.Stream.Records {
		p, err := sess.Decrypt(side, rec)
		if err != nil {
			continue // one undecryptable record is not the whole stream
		}
		if len(p.Data) == 0 {
			continue
		}
		buf = append(buf, p.Data...)
		// The record's OWN frame list, not an offset lookup: tlsdis already
		// records which frames carried each record, and re-deriving it from a
		// ciphertext offset would be a second answer to a question the
		// dissector has already answered.
		frame := 0
		if len(rec.Packets) > 0 {
			frame = rec.Packets[0]
		}
		as.recFrames = append(as.recFrames, recSpan{end: len(buf), frame: frame})
	}
	as.bytes = buf
	return nil
}

// isToPort reports whether a direction is the one dialling a low port, i.e. the
// client side.
func isToPort(d *netdis.Direction) bool { return d.Flow.Dst.Port < d.Flow.Src.Port }

// adu is one MBAP frame located in a stream.
type adu struct {
	off  int
	txid uint16
	unit uint8
	pdu  []byte
}

// adus walks an application stream and yields every complete MBAP frame with
// its byte offset. It is deliberately tolerant: a stream that begins mid-ADU,
// or ends truncated, yields the frames it can rather than none.
func adus(b []byte) []adu {
	var out []adu
	for off := 0; off+7 <= len(b); {
		length := int(b[off+4])<<8 | int(b[off+5])
		proto := int(b[off+2])<<8 | int(b[off+3])
		// Protocol id 0 and a sane length are the only two things that make a
		// candidate an MBAP header; anything else is resynchronised past.
		if proto != 0 || length < 2 || length > 253+1 {
			off++
			continue
		}
		end := off + 6 + length
		if end > len(b) {
			break
		}
		out = append(out, adu{
			off:  off,
			txid: uint16(b[off])<<8 | uint16(b[off+1]),
			unit: b[off+6],
			pdu:  b[off+7 : end],
		})
		off = end
	}
	return out
}

// writes decodes this stream's register-writing requests.
func (a *appStream) writes(frameTime map[int]time.Time, chain []Block) []Write {
	var out []Write
	for _, f := range adus(a.bytes) {
		pdu := mbapref.DecodePDU(f.pdu, mbapref.FromClient)
		if pdu.FC != mbapref.FCWriteSingle && pdu.FC != mbapref.FCWriteMultiple {
			continue
		}
		frame := a.frameAt(f.off)
		w := Write{
			Time: frameTime[frame], Frame: frame, Flow: a.flow, TLS: a.tls,
			Unit: f.unit, FC: pdu.FC, Addr: pdu.Addr, Count: pdu.Count, Values: pdu.Values,
		}
		if w.FC == mbapref.FCWriteSingle {
			w.Count = 1
		}
		for _, b := range chain {
			if b.Contains(w.Addr) {
				w.Model, w.ModelBase = b.Model, b.Base
				break
			}
		}
		out = append(out, w)
	}
	return out
}

// discoverBlocks reconstructs the served SunSpec chain from ONE conversation's
// own discovery reads.
//
// A model header is a TWO-REGISTER read whose response is (modelID, length),
// and the sequence of them is the device's chain. Request and response are
// paired by MBAP transaction id — the field the protocol itself pairs them with
// — so a pairing this makes is a pairing the device made.
//
// It needs BOTH directions: the request carries the address, the response
// carries what is at it. A conversation captured one-way yields no chain, which
// is reported rather than guessed around (every write then reads model=unknown
// and its address stands alone, which is still a checkable claim).
//
// Count==2 exactly, deliberately. A gateway that reads a whole model in one
// request is not announcing a header, and treating any long read's first two
// registers as (id, len) would invent blocks out of measurement data.
func discoverBlocks(c *conv, frameTime map[int]time.Time) []Block {
	if c.toDevice == nil || c.fromDevice == nil {
		return nil
	}
	type req struct {
		addr  uint16
		frame int
	}
	pending := map[uint16]req{}
	for _, f := range adus(c.toDevice.bytes) {
		pdu := mbapref.DecodePDU(f.pdu, mbapref.FromClient)
		if pdu.FC == mbapref.FCReadHolding && pdu.Count == 2 {
			pending[f.txid] = req{addr: pdu.Addr, frame: c.toDevice.frameAt(f.off)}
		}
	}
	var out []Block
	for _, f := range adus(c.fromDevice.bytes) {
		r, ok := pending[f.txid]
		if !ok {
			continue
		}
		pdu := mbapref.DecodePDU(f.pdu, mbapref.FromServer)
		if pdu.FC != mbapref.FCReadHolding || len(pdu.Values) != 2 {
			continue
		}
		id, length := pdu.Values[0], pdu.Values[1]
		if !plausibleHeader(id, length) {
			continue
		}
		out = append(out, Block{
			Model: id, Base: r.addr + 2, Length: length,
			Frame: c.fromDevice.frameAt(f.off),
		})
	}
	return out
}

// conv is one Modbus conversation: the two directions that pair into
// request/response.
type conv struct {
	toDevice   *appStream
	fromDevice *appStream
}

// maxModelLen is the largest declared model length this tool will believe.
//
// It is a SANITY BOUND, not a claim about the standard: SunSpec sets no such
// limit, and the point is only that a two-register read whose second word is
// enormous is far more likely to be the low half of a uint32 than a model
// length. The largest model this bench serves is 701 at 153 registers, and the
// trip models at ~380; 1024 leaves room and still rejects the register values
// that produce phantoms. A genuine model longer than this is DROPPED and
// counted, never silently mislabelled — its writes then read model=unknown with
// their address, which is honest.
const maxModelLen = 1024

// plausibleHeader reports whether a two-register read result can be a SunSpec
// model header at all.
//
// GATE FINDING D1. This used to reject only id==0xFFFF and length==0, which
// left id==0 UNGUARDED — and id==0 is exactly what the high word of a uint32
// below 65536 looks like. The reversion work made polling RvrtTms/RvrtRem
// ROUTINE, so a poll of WSetRvrtTms=300 read back as the header "model 0,
// length 300" and manufactured a block at the polled address. Not a corner
// case: a phantom with a lower base SHADOWED a real block, because the chain is
// sorted by base and the matcher takes the first containing block — so a write
// got the wrong axis AND the wrong offset, printed as discovered structure.
//
//	id 0        the high word of any uint32 under 65536 — the shape of every
//	            reversion-timer poll on this bench
//	id 0xFFFF   the SunSpec end marker
//	id > 799 and below the vendor range
//	            not a model number; standard models stop well short and vendor
//	            blocks start at 64000
//	length 0    not a block
//	length > maxModelLen
//	            see above
func plausibleHeader(id, length uint16) bool {
	if id == 0 || id == 0xFFFF {
		return false
	}
	if id > 799 && (id < 64000 || id > 65533) {
		return false
	}
	return length >= 1 && length <= maxModelLen
}

// rejectOverlaps drops every block that overlaps another, and reports how many
// went.
//
// This is the rule that makes SHADOWING IMPOSSIBLE, which is why it exists
// separately from plausibleHeader rather than being folded into it: a real
// SunSpec chain does not overlap itself, so an overlap proves at least one of
// the pair is a phantom — and there is no honest way to pick which. Keeping the
// earlier-discovered one would be a guess printed as structure. Dropping both
// costs a label and keeps the address, and an unlabelled address is still a
// checkable claim while a confidently wrong axis is not.
func rejectOverlaps(in []Block) (kept []Block, dropped int) {
	bad := make([]bool, len(in))
	for i := range in {
		for j := i + 1; j < len(in); j++ {
			if in[i].overlaps(in[j]) {
				bad[i], bad[j] = true, true
			}
		}
	}
	for i, b := range in {
		if bad[i] {
			dropped++
			continue
		}
		kept = append(kept, b)
	}
	return kept, dropped
}

// dedupeBlocks keeps one entry per (model, base), lowest frame first.
func dedupeBlocks(in []Block) []Block {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Frame < in[j].Frame })
	seen := map[uint32]bool{}
	var out []Block
	for _, b := range in {
		k := uint32(b.Model)<<16 | uint32(b.Base)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Base < out[j].Base })
	return out
}

// mentionsOf finds every frame in which a literal appears, deduplicated and in
// frame order.
func mentionsOf(streams []*appStream, frameTime map[int]time.Time, lit string) []Mention {
	needle := []byte(lit)
	seen := map[int]bool{}
	var frames []int
	for _, s := range streams {
		for off := 0; off < len(s.bytes); {
			i := bytes.Index(s.bytes[off:], needle)
			if i < 0 {
				break
			}
			f := s.frameAt(off + i)
			if !seen[f] {
				seen[f] = true
				frames = append(frames, f)
			}
			off += i + len(needle)
		}
	}
	sort.Ints(frames)
	out := make([]Mention, 0, len(frames))
	for _, f := range frames {
		out = append(out, Mention{Frame: f, Time: frameTime[f]})
	}
	return out
}

// findWindow builds the mRID's window: its mentions, the discontinuities
// between them, and any supersession bound.
func findWindow(streams []*appStream, frameTime map[int]time.Time, mrid, until string, settle time.Duration) (*Window, error) {
	ms := mentionsOf(streams, frameTime, mrid)
	if len(ms) == 0 {
		return nil, nil
	}
	w := &Window{Mentions: ms, Settle: settle}
	for i := 1; i < len(ms); i++ {
		if d := ms[i].Time.Sub(ms[i-1].Time); d > settle {
			w.Gaps = append(w.Gaps, Gap{
				AfterFrame: ms[i-1].Frame, BeforeFrame: ms[i].Frame, Duration: d,
			})
		}
	}
	if until != "" {
		bs := mentionsOf(streams, frameTime, until)
		if len(bs) == 0 {
			return nil, fmt.Errorf("writeset: the superseding mRID %q does not appear in this capture, "+
				"so there is no supersession boundary to cut at", until)
		}
		t := bs[0].Time
		w.Bound, w.BoundMRID = &t, until
	}
	return w, nil
}

// mridPattern matches the <mRID> elements a control document carries. It is how
// co-residency is detected: two mRIDs in ONE frame are two controls in one
// served list.
var mridPattern = regexp.MustCompile(`<mRID>([^<]{1,128})</mRID>`)

// coResident finds the OTHER mRIDs the capture carries and says how each
// relates to the target's window.
//
// GATE FINDING D3, and it is the headline use case. A supersession pair is
// normally in exactly ONE DERControlList document: both mRIDs appear in the
// same frame, so both get identical mention sets, so each is credited with the
// other's writes — which is precisely the distinction PC-001 is about. No
// tightening of a time rule can separate two controls delivered in one frame,
// so the tool's obligation is to SAY SO, loudly, and to offer the cut that can
// separate them (Options.UntilMRID).
func coResident(streams []*appStream, frameTime map[int]time.Time, target string, w *Window) []CoResident {
	inFrame := map[string]map[int]bool{}
	for _, s := range streams {
		for _, m := range mridPattern.FindAllSubmatchIndex(s.bytes, -1) {
			id := string(s.bytes[m[2]:m[3]])
			if id == target {
				continue
			}
			f := s.frameAt(m[0])
			if inFrame[id] == nil {
				inFrame[id] = map[int]bool{}
			}
			inFrame[id][f] = true
		}
	}
	targetFrames := map[int]bool{}
	for _, m := range w.Mentions {
		targetFrames[m.Frame] = true
	}
	var out []CoResident
	for id, frames := range inFrame {
		c := CoResident{MRID: id}
		for f := range frames {
			if targetFrames[f] {
				c.SharedFrames = append(c.SharedFrames, f)
			}
			if t := frameTime[f]; w.covers(t) {
				c.MentionsInWindow++
			}
		}
		if len(c.SharedFrames) == 0 && c.MentionsInWindow == 0 {
			continue
		}
		sort.Ints(c.SharedFrames)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MRID < out[j].MRID })
	return out
}

// CoResident is another control whose delivery overlaps the target's window.
type CoResident struct {
	MRID string
	// SharedFrames are frames carrying BOTH mRIDs — one document, two controls,
	// and therefore writes this tool cannot tell apart by time at all.
	SharedFrames []int
	// MentionsInWindow counts this control's own mentions inside the target's
	// attribution window.
	MentionsInWindow int
}

// Render writes the report. The format is line-oriented and stable: one write
// per line, fixed field order, every field labelled, so a bundle manifest can
// cite a line and a reader can grep for an address.
func (r *Result) Render(out io.Writer) {
	fmt.Fprintf(out, "# writeset capture=%s\n", r.Capture)
	if r.KeyLog != "" {
		fmt.Fprintf(out, "# keylog=%s\n", r.KeyLog)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(out, "# note: %s\n", n)
	}
	if len(r.Chain) == 0 {
		fmt.Fprintf(out, "# chain: none discovered — no model-header read is in this capture, so every "+
			"write below reports model=unknown and its address is the only identification\n")
	} else {
		var parts []string
		for _, b := range r.Chain {
			parts = append(parts, fmt.Sprintf("M%d@%d+%d", b.Model, b.Base, b.Length))
		}
		fmt.Fprintf(out, "# chain (derived from this capture's own header reads): %s\n", strings.Join(parts, " "))
	}

	writes := r.Writes
	if r.Window != nil {
		w := r.Window
		fmt.Fprintf(out, "# mrid=%s mentions=%d span=[%s .. %s]\n",
			r.MRID, len(w.Mentions), ts(w.First()), ts(w.Last()))
		fmt.Fprintf(out, "# attribution rule: a write is attributed when its frame time falls within the "+
			"settle margin (%s) of SOME mention of this mRID — NOT merely between the first and last. "+
			"On a polled protocol a control is re-served every poll cycle, so the span above is how long "+
			"it was OFFERED, not how long it was acting.\n", w.Settle)
		for _, m := range w.Mentions {
			fmt.Fprintf(out, "#   mention frame=%d ts=%s covers=[%s .. %s]\n",
				m.Frame, ts(m.Time), ts(m.Time), ts(m.Time.Add(w.Settle)))
		}
		for _, g := range w.Gaps {
			fmt.Fprintf(out, "#   GAP %s between frame=%d and frame=%d — longer than the settle margin, "+
				"so nothing in it is attributed; a span-shaped rule would have swallowed it\n",
				g.Duration, g.AfterFrame, g.BeforeFrame)
		}
		if w.Bound != nil {
			fmt.Fprintf(out, "# bound: cut at %s, the first mention of the superseding mRID %s — no write "+
				"at or after that instant is attributed to %s\n", ts(*w.Bound), w.BoundMRID, r.MRID)
		}
		writes = r.Attributed()
		fmt.Fprintf(out, "# excluded=%d (writes in this capture outside the window)\n", r.Excluded)

		// THE BANNER. A clean extraction and a confounded one must not have to
		// be told apart by comparing mention lists.
		if !r.Confounded() {
			fmt.Fprintf(out, "# confounded=no — no other control shares a frame with this one or is "+
				"mentioned inside its window\n")
		} else {
			fmt.Fprintf(out, "# confounded=YES\n")
			fmt.Fprintf(out, "#\n")
			fmt.Fprintf(out, "# !! CONFOUNDED ATTRIBUTION — THE WRITES BELOW MAY NOT ALL BE THIS CONTROL'S.\n")
			for _, c := range r.CoResidents {
				if len(c.SharedFrames) > 0 {
					cut := "Re-run with -writes-until naming the superseding mRID to cut at the " +
						"supersession boundary."
					if w.BoundMRID == c.MRID {
						cut = "THE BOUND ABOVE CUTS AT THIS CONTROL, so the writes below are the ones " +
							"before it arrived — the co-residency is disclosed because it is a fact " +
							"about the capture, not because the cut failed to address it."
					}
					fmt.Fprintf(out, "# !!   %s is in the SAME FRAME(S) as this control: %v. One document, "+
						"two controls: they have identical mention sets, so NO time rule can tell their "+
						"writes apart. %s\n", c.MRID, c.SharedFrames, cut)
					continue
				}
				fmt.Fprintf(out, "# !!   %s is mentioned %d time(s) inside this control's window; writes "+
					"in those intervals could be either control's\n", c.MRID, c.MentionsInWindow)
			}
			fmt.Fprintf(out, "#\n")
		}
	}

	byAxis := map[string][]Write{}
	var axes []string
	for _, w := range writes {
		a := w.Axis()
		if _, ok := byAxis[a]; !ok {
			axes = append(axes, a)
		}
		byAxis[a] = append(byAxis[a], w)
	}
	sort.Strings(axes)

	fmt.Fprintf(out, "# axes=%d writes=%d\n", len(axes), len(writes))
	for _, a := range axes {
		ws := byAxis[a]
		fmt.Fprintf(out, "axis %s writes=%d\n", a, len(ws))
		for _, w := range ws {
			fmt.Fprintf(out, "  write axis=%s ts=%s frame=%d addr=%d count=%d fc=0x%02X unit=%d off=%d values=%s flow=%s tls=%t\n",
				a, ts(w.Time), w.Frame, w.Addr, w.Count, w.FC, w.Unit, w.Offset(), vals(w.Values), w.Flow, w.TLS)
		}
	}
	if len(writes) == 0 {
		fmt.Fprintf(out, "# no register writes in scope\n")
	}
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func vals(v []uint16) string {
	if len(v) == 0 {
		return "-"
	}
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}
