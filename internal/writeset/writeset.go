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

// DefaultTLSPorts are the ports whose Modbus rides inside TLS. 802 is Secure
// SunSpec Modbus; 8021 is where the unprivileged mbapsdev binds.
var DefaultTLSPorts = []uint16{802, 8021}

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
	// PlainPorts / TLSPorts override the port sets.
	PlainPorts, TLSPorts []uint16
	// MRID, when set, restricts the report to writes attributed to that control.
	MRID string
	// Settle extends the mRID window past its last mention. Zero uses
	// DefaultSettle.
	Settle time.Duration
}

// Write is one register-writing Modbus request, as it appeared on the wire.
type Write struct {
	Time  time.Time
	Frame int    // 1-based capture frame index that delivered the ADU's first byte
	Flow  string // "src > dst"
	TLS   bool   // recovered from inside TLS
	Unit  uint8
	FC    uint8
	Addr  uint16
	Count uint16
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

// Window is the interval an mRID's writes were attributed over.
type Window struct {
	First, Last time.Time // first and last frame mentioning the mRID
	Until       time.Time // Last + settle: the attribution bound
	Settle      time.Duration
	FirstFrame  int
	LastFrame   int
	Mentions    int
}

// Result is one extraction.
type Result struct {
	Capture  string
	KeyLog   string
	Chain    []Block
	Writes   []Write // every write found, in wire order
	MRID     string
	Window   *Window // nil when no mRID was given
	Excluded int     // writes outside the window, when an mRID was given
	Notes    []string
}

// Attributed returns the writes inside the mRID window, or all writes when no
// mRID was given.
func (r *Result) Attributed() []Write {
	if r.Window == nil {
		return r.Writes
	}
	var out []Write
	for _, w := range r.Writes {
		if !w.Time.Before(r.Window.First) && !w.Time.After(r.Window.Until) {
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

	// Every application-layer byte stream in the capture, paired into Modbus
	// conversations (which the chain derivation needs, since the request
	// carries the address and the response carries what is at it).
	convs, streams := collectStreams(asm, plain, tlsPorts, kl, res)

	for _, c := range convs {
		res.Chain = append(res.Chain, discoverBlocks(c, frameTime)...)
	}
	res.Chain = dedupeBlocks(res.Chain)

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
		w := findWindow(streams, frameTime, opts.MRID, settle)
		if w == nil {
			return nil, fmt.Errorf("writeset: the mRID %q does not appear anywhere in %s — "+
				"either the control was not carried on this leg's capture, or the northbound traffic "+
				"is TLS and no usable key log was supplied", opts.MRID, capPath)
		}
		res.Window = w
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
func collectStreams(asm *netdis.Assembler, plain, tlsPorts []uint16, kl *keylog.Log, res *Result) ([]*conv, []*appStream) {
	var convs []*conv
	var out []*appStream
	seen := map[string]bool{}

	add := func(port uint16, isTLS bool) {
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
					modbus: true, toDevice: toDevice,
				}
				if !isTLS {
					as.bytes = d.Bytes.Bytes()
				} else if kl == nil {
					res.Notes = append(res.Notes, fmt.Sprintf(
						"%s is TLS and no key log was available — its writes are not in this report", as.flow))
					continue
				} else if err := decryptInto(as, s, d, kl); err != nil {
					res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", as.flow, err))
					continue
				}
				out = append(out, as)
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
		add(p, false)
	}
	for _, p := range tlsPorts {
		add(p, true)
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
		// 0xFFFF is the SunSpec end marker and length 0 is not a block.
		if id == 0xFFFF || length == 0 {
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

// findWindow locates the mRID in any readable stream and returns its window.
func findWindow(streams []*appStream, frameTime map[int]time.Time, mrid string, settle time.Duration) *Window {
	needle := []byte(mrid)
	var frames []int
	for _, s := range streams {
		for off := 0; ; {
			i := bytes.Index(s.bytes[off:], needle)
			if i < 0 {
				break
			}
			frames = append(frames, s.frameAt(off+i))
			off += i + len(needle)
		}
	}
	if len(frames) == 0 {
		return nil
	}
	sort.Ints(frames)
	first, last := frames[0], frames[len(frames)-1]
	w := &Window{
		First: frameTime[first], Last: frameTime[last],
		Settle: settle, FirstFrame: first, LastFrame: last, Mentions: len(frames),
	}
	w.Until = w.Last.Add(settle)
	return w
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
		fmt.Fprintf(out, "# mrid=%s mentions=%d window=[%s .. %s] settle=%s bound=%s frames=%d..%d\n",
			r.MRID, w.Mentions, ts(w.First), ts(w.Last), w.Settle, ts(w.Until), w.FirstFrame, w.LastFrame)
		fmt.Fprintf(out, "# attribution rule: a write is attributed to this mRID when its frame time is "+
			"at or after the FIRST frame mentioning the mRID and at or before the LAST such frame plus "+
			"the settle margin. Writes outside that interval are excluded and counted below.\n")
		writes = r.Attributed()
		fmt.Fprintf(out, "# excluded=%d (writes in this capture outside the window)\n", r.Excluded)
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
