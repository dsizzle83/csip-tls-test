package mbapref

// differential.go asks the four questions in doc.go and reports the answers.
//
// # The seam, and why there is one
//
// Every check in this repo needs teeth: a demonstration that it FAILS against
// a deliberately non-conformant peer, because a check that has only ever
// passed proves nothing about the check. A differential against a real package
// has no natural way to be wrong on purpose — lexa-proto/mbap is correct, so
// running it produces agreement, and agreement is exactly the evidence a
// reader should not accept.
//
// So the subject under comparison is an interface. [ProtoSubject] is the real
// one and is what the fuzz target and the corpus runs use. differential_test.go
// substitutes framers that are wrong in one specific way each — one that
// resynchronises after a bad header, one that repairs an inconsistent length,
// one that accepts a truncated tail as a whole frame — and asserts that the
// corresponding question fires and that the others stay quiet. A finding that
// fires for everything is as useless as one that fires for nothing.
//
// # Truncation is classified structurally, not by error text
//
// A finite buffer ends where it ends, and both readers hit the end. That is
// not a disagreement about the protocol and must not be reported as one. The
// classification is made from a fact neither reader gets to editorialise
// about: whether the subject had consumed the whole buffer at the moment it
// failed. If it had, the stop was truncation; if bytes remained, the subject
// refused bytes it could see, and that is a framing violation. No error string
// is matched anywhere in this file, which matters because error text is not
// API and a differential that depends on it breaks silently when someone
// improves a message.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"lexa-proto/mbap"
)

// StopClass is why a reader stopped short of the end of a buffer.
type StopClass string

const (
	// StopClean means the buffer ended exactly on a frame boundary.
	StopClean StopClass = "clean"
	// StopTruncated means the reader ran out of buffer mid-frame. On a live
	// socket this is "read more"; on a capture it is an ordinary tail.
	StopTruncated StopClass = "truncated"
	// StopViolation means the reader refused bytes it could still see.
	StopViolation StopClass = "violation"
)

// Framing is one reader's answer for one buffer.
type Framing struct {
	Frames []Frame
	Stop   StopClass
	// StopOff is the offset of the first byte the reader did not consume.
	StopOff int
	// Reason is the reader's own account of a non-clean stop, kept for the
	// report. It is NEVER compared — see the note above.
	Reason string
}

// Subject is a reader under comparison. It exists so the differential can be
// pointed at something deliberately broken; see the seam note above.
//
// It covers all four layers the questions ask about — framing, re-encoding,
// request parsing and response parsing — because a seam that covers only
// framing leaves three of the four questions untestable, and an untested
// question is one that has never been shown capable of failing.
//
// The request/response parsers are normalised into this package's own [PDU]
// type by the adapter in [ProtoSubject]. That normalisation is a small,
// visible piece of code rather than a shared struct on purpose: it is the one
// place the two vocabularies meet, and keeping it in one function means a
// disagreement can never be an artefact of a field the two sides happened to
// name the same thing.
type Subject interface {
	Name() string

	// Frame splits a buffer into ADUs.
	Frame(b []byte) Framing

	// Encode re-serialises a frame the subject produced.
	Encode(f Frame) ([]byte, error)

	// ParseRequest decodes a request-direction PDU. A returned error means the
	// subject refused it.
	ParseRequest(pdu []byte) (PDU, error)

	// ParseReadResponse decodes a read response against the request it
	// answers.
	ParseReadResponse(req PDU, pdu []byte) ([]uint16, error)

	// ParseWriteResponse verifies a write echo against the request it answers.
	ParseWriteResponse(req PDU, pdu []byte) error
}

// Reference frames b with this package's own reader, in Subject shape, so the
// two sides of the comparison are literally the same type.
func Reference(b []byte) Framing {
	frames, fault := FrameStream(b)
	f := Framing{Frames: frames, Stop: StopClean, StopOff: len(b)}
	if fault != nil {
		f.StopOff = fault.Off
		f.Reason = fault.Reason
		f.Stop = StopViolation
		if fault.Truncated {
			f.Stop = StopTruncated
		}
	}
	return f
}

// countingReader records how many bytes a reader consumed and whether it ever
// reached the end of the buffer. Both facts are needed to classify a stop
// without reading the subject's mind: the count gives the offset, and
// hitEOF distinguishes "ran out" from "refused".
type countingReader struct {
	b      []byte
	off    int
	hitEOF bool
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		r.hitEOF = true
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

type protoSubject struct{}

// ProtoSubject is the product's reader: lexa-proto/mbap, the package the
// gateway itself frames with. This is the whole point of the exercise.
func ProtoSubject() Subject { return protoSubject{} }

func (protoSubject) Name() string { return "lexa-proto/mbap" }

func (protoSubject) Frame(b []byte) Framing {
	r := &countingReader{b: b}
	out := Framing{Stop: StopClean}
	for {
		start := r.off
		r.hitEOF = false
		adu, err := mbap.Decode(r)
		if err != nil {
			out.StopOff = start
			switch {
			case errors.Is(err, io.EOF) && start == len(b):
				out.Stop = StopClean
				out.StopOff = len(b)
			case r.hitEOF:
				// The subject asked for bytes the buffer did not have. It ran
				// out; it did not refuse.
				out.Stop = StopTruncated
				out.Reason = err.Error()
			default:
				out.Stop = StopViolation
				out.Reason = err.Error()
			}
			return out
		}
		out.Frames = append(out.Frames, Frame{
			TID: adu.TID, PID: adu.PID, Length: adu.Length, Unit: adu.UnitID,
			PDU: adu.PDU, Off: start, End: r.off,
		})
		if r.off >= len(b) {
			out.StopOff = len(b)
			return out
		}
	}
}

func (protoSubject) Encode(f Frame) ([]byte, error) {
	return mbap.Encode(mbap.ADU{
		Header: mbap.Header{TID: f.TID, PID: f.PID, Length: f.Length, UnitID: f.Unit},
		PDU:    f.PDU,
	})
}

// ParseRequest is the adapter between lexa-proto's two request types and this
// package's single one. It tries the read shape and then the write shape,
// which is what the gateway's server layer does with the function code in
// hand; a PDU neither accepts is refused with the error the reader gave for
// the arm its function code selected, so the message names the real rule.
func (protoSubject) ParseRequest(pdu []byte) (PDU, error) {
	if len(pdu) == 0 {
		return PDU{}, fmt.Errorf("empty pdu")
	}
	switch pdu[0] {
	case mbap.FCReadHolding, mbap.FCReadInput:
		r, err := mbap.ParseReadReq(pdu)
		if err != nil {
			return PDU{}, err
		}
		return PDU{Kind: KindReadReq, FC: r.FC, Addr: r.Addr, Count: r.Count}, nil
	case mbap.FCWriteSingle, mbap.FCWriteMultiple:
		w, err := mbap.ParseWriteReq(pdu)
		if err != nil {
			return PDU{}, err
		}
		return PDU{Kind: KindWriteReq, FC: w.FC, Addr: w.Addr,
			Count: uint16(len(w.Values)), Values: w.Values}, nil
	default:
		return PDU{Kind: KindUnsupported, FC: pdu[0]}, nil
	}
}

// PanicError reports that a subject panicked instead of returning.
//
// A differential must survive its subject crashing, or one defect stops the
// exploration of every other. But surviving must not mean forgiving: the panic
// is converted into a refusal so the comparison can continue, and it is
// attributed to DEFECT-READRESP-1BYTE by name — a suppression that exists to
// be deleted, not a tolerance that grows.
type PanicError struct {
	Value any
}

func (e *PanicError) Error() string { return fmt.Sprintf("subject panicked: %v", e.Value) }

func (protoSubject) ParseReadResponse(req PDU, pdu []byte) (vals []uint16, err error) {
	defer func() {
		if r := recover(); r != nil {
			vals, err = nil, &PanicError{Value: r}
		}
	}()
	return mbap.ParseReadResp(mbap.ReadReq{FC: req.FC, Addr: req.Addr, Count: req.Count}, pdu)
}

func (protoSubject) ParseWriteResponse(req PDU, pdu []byte) error {
	return mbap.ParseWriteResp(mbap.WriteReq{FC: req.FC, Addr: req.Addr, Values: req.Values}, pdu)
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// Class says what kind of claim a finding falsifies, and it is the difference
// between a fuzz oracle that works and one that cries wolf every millisecond.
//
// A differential finding says THE TWO READERS DISAGREED about the same bytes.
// That is always interesting, whatever the bytes were, because two correct
// readers agree on every input including nonsense.
//
// A traffic finding says THE BYTES THEMSELVES VIOLATED THE PROTOCOL — a device
// answered a request for function 0x30 with an exception for function 0x03,
// say. Against a real capture that is a genuine finding about a real peer.
// Against a fuzzer it is noise by construction: the fuzzer's whole job is to
// invent traffic no conforming peer would send, so a traffic check run over
// fuzzer output fires constantly and says nothing.
//
// The distinction cost a red fuzz run to learn. FuzzMBAPExchange found
// `01 30 30 30 30 30` answered by `01 83 30` within a second and reported it
// as a divergence, which it is not: both readers read those bytes identically
// and correctly, and the only thing wrong was the imaginary device. The oracle
// filters to Differential; the capture-driven runs report both.
type Class string

const (
	ClassDifferential Class = "differential"
	ClassTraffic      Class = "traffic"
)

// Question is which of the four claims a finding falsifies.
type Question string

const (
	QFraming    Question = "FRAMING"
	QSemantics  Question = "SEMANTICS"
	QAcceptance Question = "ACCEPTANCE"
	QIdentity   Question = "IDENTITY"
)

// Finding is one falsified claim.
//
// Divergence is set when the difference is one of the enumerated, justified
// ones; such a finding is informational and Compare's caller filters it out.
// An empty Divergence on an ACCEPTANCE finding is the interesting case and the
// reason the enumeration is short.
type Finding struct {
	Question Question
	// Class defaults to ClassDifferential: the zero value of the field is the
	// empty string and [Finding.Kind] reads that as differential, so a new
	// check is a reader-disagreement check unless its author says otherwise.
	// That is the safe default — a traffic check miscategorised as
	// differential makes noise and gets noticed, while the other way round
	// silently drops findings.
	Class      Class
	Off        int
	Subject    string
	Detail     string
	Divergence string
}

// Kind returns f.Class with the zero value resolved.
func (f Finding) Kind() Class {
	if f.Class == "" {
		return ClassDifferential
	}
	return f.Class
}

func (f Finding) String() string {
	s := fmt.Sprintf("%s at offset %d: %s", f.Question, f.Off, f.Detail)
	if f.Kind() == ClassTraffic {
		s = "[traffic] " + s
	}
	if f.Divergence != "" {
		s += " [" + f.Divergence + ", enumerated]"
	}
	return s
}

// Unenumerated reports whether f is a real finding rather than a known,
// justified difference.
func (f Finding) Unenumerated() bool { return f.Divergence == "" }

// Unenumerated filters a finding list down to the ones that matter.
func Unenumerated(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Unenumerated() {
			out = append(out, f)
		}
	}
	return out
}

// Differential filters to reader-disagreement findings: the ones whose meaning
// does not depend on the input having been plausible traffic. This is what a
// fuzz oracle must assert on; see [Class].
func Differential(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Unenumerated() && f.Kind() == ClassDifferential {
			out = append(out, f)
		}
	}
	return out
}

// Traffic filters to findings about the bytes rather than the readers. It is
// meaningful only over real captured traffic.
func Traffic(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Kind() == ClassTraffic {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------

// Compare frames b with both readers and answers all four questions.
//
// dir says which end of the conversation produced b. It is required rather
// than inferred because the same five bytes are a read request one way and a
// write-single response the other, and a differential that guessed would
// manufacture disagreements out of its own guess.
func Compare(sub Subject, b []byte, dir Dir) []Finding {
	var out []Finding
	ref := Reference(b)
	got := sub.Frame(b)

	out = append(out, compareFraming(sub.Name(), b, ref, got)...)

	// Semantics and identity are only askable about frames BOTH accepted at
	// the same place. Comparing frame i of one against frame i of the other
	// after a framing divergence compares unrelated bytes and produces a
	// cascade of noise from a single root cause.
	n := min(len(ref.Frames), len(got.Frames))
	for i := 0; i < n; i++ {
		rf, gf := ref.Frames[i], got.Frames[i]
		if rf.Off != gf.Off || rf.End != gf.End {
			break
		}
		out = append(out, compareHeader(sub.Name(), rf, gf)...)
		out = append(out, compareIdentity(sub, b, rf, gf)...)
		out = append(out, comparePDU(sub, rf, dir)...)
	}
	return out
}

func compareFraming(name string, b []byte, ref, got Framing) []Finding {
	var out []Finding

	// Boundary-by-boundary, which localises the divergence to the first frame
	// that moved rather than reporting "12 frames versus 11".
	n := min(len(ref.Frames), len(got.Frames))
	for i := 0; i < n; i++ {
		rf, gf := ref.Frames[i], got.Frames[i]
		if rf.Off != gf.Off || rf.End != gf.End {
			out = append(out, Finding{
				Question: QFraming, Off: rf.Off, Subject: name,
				Detail: fmt.Sprintf("frame %d boundaries differ: reference [%d,%d), %s [%d,%d)",
					i, rf.Off, rf.End, name, gf.Off, gf.End),
			})
			return out // everything after this is downstream of one root cause
		}
	}

	if ref.Stop == got.Stop && ref.StopOff == got.StopOff && len(ref.Frames) == len(got.Frames) {
		return out
	}

	// A stop difference is an acceptance difference, and acceptance
	// differences are the ones the enumeration governs.
	out = append(out, acceptanceFinding(name, b, ref, got))
	return out
}

// acceptanceFinding builds the finding for a stop-class or frame-count
// difference and attributes it to an enumerated divergence when it is one.
func acceptanceFinding(name string, b []byte, ref, got Framing) Finding {
	f := Finding{
		Question: QAcceptance,
		Off:      min(ref.StopOff, got.StopOff),
		Subject:  name,
		Detail: fmt.Sprintf("reference framed %d frame(s) and stopped %s at %d (%s); %s framed %d and stopped %s at %d (%s)",
			len(ref.Frames), ref.Stop, ref.StopOff, orNone(ref.Reason),
			name, len(got.Frames), got.Stop, got.StopOff, orNone(got.Reason)),
	}
	// DIV-LEN2: the product refuses a Length of 2 at the framing layer where
	// the reference frames it and judges it at the PDU layer.
	//
	// The attribution reads the length field out of the BUFFER rather than out
	// of either reader's output, and that is not fussiness. The first version
	// of this code looked the length up in the reference's frame list, which
	// works only when the reference actually framed the ADU — and the
	// interesting case includes one where it did not, because a length-2
	// header followed by no body is truncated to the reference and a framing
	// violation to the product. Ninety seconds of fuzzing found that hole. An
	// attribution that depends on one side's success cannot classify the cases
	// where that side also stopped.
	if got.Stop == StopViolation && lengthFieldAt(b, got.StopOff) == MinLengthField {
		f.Divergence = "DIV-LEN2"
	}
	return f
}

// lengthFieldAt reads the MBAP length field of the header beginning at off,
// or 0 when off does not begin a whole header.
func lengthFieldAt(b []byte, off int) uint16 {
	if off < 0 || off+6 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off+4 : off+6])
}

func orNone(s string) string {
	if s == "" {
		return "no reason"
	}
	return s
}

func compareHeader(name string, rf, gf Frame) []Finding {
	var out []Finding
	add := func(what string, want, got any) {
		out = append(out, Finding{
			Question: QSemantics, Off: rf.Off, Subject: name,
			Detail: fmt.Sprintf("%s: reference %v, %s %v", what, want, name, got),
		})
	}
	if rf.TID != gf.TID {
		add("transaction id", rf.TID, gf.TID)
	}
	if rf.PID != gf.PID {
		add("protocol id", rf.PID, gf.PID)
	}
	if rf.Length != gf.Length {
		add("length field", rf.Length, gf.Length)
	}
	if rf.Unit != gf.Unit {
		add("unit id", rf.Unit, gf.Unit)
	}
	if !bytes.Equal(rf.PDU, gf.PDU) {
		add("pdu bytes", fmt.Sprintf("% x", rf.PDU), fmt.Sprintf("% x", gf.PDU))
	}
	return out
}

// compareIdentity is the canonicalisation claim: a frame that decodes must
// re-encode to the bytes it came from, through BOTH encoders.
//
// This is the check that catches a decoder which silently repairs its input,
// and repair is not a hypothetical vice. A reader that recomputes a length
// field it did not like, or drops a trailing byte it did not expect, hands the
// layer above it a message the peer never sent. On this device that layer
// writes registers on an inverter.
func compareIdentity(sub Subject, b []byte, rf, gf Frame) []Finding {
	name := sub.Name()
	var out []Finding
	orig := b[rf.Off:rf.End]

	if re, err := Encode(rf); err != nil {
		out = append(out, Finding{
			Question: QIdentity, Off: rf.Off, Subject: "reference",
			Detail: fmt.Sprintf("reference decoded a frame it cannot re-encode: %v", err),
		})
	} else if !bytes.Equal(re, orig) {
		out = append(out, Finding{
			Question: QIdentity, Off: rf.Off, Subject: "reference",
			Detail: fmt.Sprintf("reference re-encode differs: got % x, want % x", re, orig),
		})
	}

	re, err := sub.Encode(gf)
	if err != nil {
		out = append(out, Finding{
			Question: QIdentity, Off: gf.Off, Subject: name,
			Detail: fmt.Sprintf("%s decoded a frame its own encoder rejects: %v", name, err),
		})
		return out
	}
	if !bytes.Equal(re, orig) {
		out = append(out, Finding{
			Question: QIdentity, Off: gf.Off, Subject: name,
			Detail: fmt.Sprintf("%s re-encode differs: got % x, want % x", name, re, orig),
		})
	}
	return out
}

// comparePDU compares the application layer for the REQUEST direction only.
//
// The product's response parsers take the request they are answering
// (ParseReadResp, ParseWriteResp), which is the right design and the reason a
// standalone response comparison is not possible here; see DIV-RESPSHAPE.
// PairStream does the response direction, where both sides have the request.
func comparePDU(sub Subject, rf Frame, dir Dir) []Finding {
	if dir != FromClient {
		return nil
	}
	name := sub.Name()
	ref := DecodePDU(rf.PDU, FromClient)
	got, err := sub.ParseRequest(rf.PDU)

	switch ref.Kind {
	case KindReadReq, KindWriteReq:
		if err != nil {
			return []Finding{{
				Question: QAcceptance, Off: rf.Off, Subject: name,
				Detail: fmt.Sprintf("reference read a %s fc=0x%02x addr=%d count=%d; %s refused: %v",
					ref.Kind, ref.FC, ref.Addr, ref.Count, name, err),
			}}
		}
		var out []Finding
		if got.Kind != ref.Kind || got.FC != ref.FC || got.Addr != ref.Addr || got.Count != ref.Count {
			return append(out, Finding{
				Question: QSemantics, Off: rf.Off, Subject: name,
				Detail: fmt.Sprintf("request shape: reference %s fc=0x%02x addr=%d count=%d; %s %s fc=0x%02x addr=%d count=%d",
					ref.Kind, ref.FC, ref.Addr, ref.Count, name, got.Kind, got.FC, got.Addr, got.Count),
			})
		}
		// Values are compared element by element rather than with a slice
		// equality, so a finding names the REGISTER that differs. On this
		// device the register number is the whole story: register 704.WMaxLimPct
		// and register 704.VarSetPct are one apart and mean utterly different
		// things.
		if len(got.Values) != len(ref.Values) {
			return append(out, Finding{
				Question: QSemantics, Off: rf.Off, Subject: name,
				Detail: fmt.Sprintf("write request value count: reference %d, %s %d", len(ref.Values), name, len(got.Values)),
			})
		}
		for i := range ref.Values {
			if ref.Values[i] != got.Values[i] {
				out = append(out, Finding{
					Question: QSemantics, Off: rf.Off, Subject: name,
					Detail: fmt.Sprintf("write request register %d: reference %d, %s %d",
						int(ref.Addr)+i, ref.Values[i], name, got.Values[i]),
				})
			}
		}
		return out

	case KindIndecipherab:
		// The reference refused. The subject accepting is the direction that
		// matters: it means the gateway would act on a message this reader
		// says is malformed, and there is no enumerated divergence that way.
		if err == nil && (got.Kind == KindReadReq || got.Kind == KindWriteReq) {
			return []Finding{{
				Question: QAcceptance, Off: rf.Off, Subject: name,
				Detail: fmt.Sprintf("reference refused the pdu (%s) but %s accepted it as %s fc=0x%02x addr=%d count=%d",
					ref.Why, name, got.Kind, got.FC, got.Addr, got.Count),
			}}
		}
		return nil

	default:
		// KindUnsupported, or an exception in the request direction. Both
		// readers decline to act; nothing to compare.
		return nil
	}
}
