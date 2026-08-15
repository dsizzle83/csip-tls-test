package gridsim

// freqdroop.go — the opModFreqDroop authoring lever (curve plan #32).
//
// ── What was missing ────────────────────────────────────────────────────────
//
// opModFreqDroop is the ONE DERControlBase mode that carries its parameters
// INLINE rather than behind a DERCurve link, and this server had no way to
// author it anywhere: neither adminCtrlReq nor adminCurveReq carried
// dBOF/dBUF/kOF/kUF/openLoopTms, and nothing ever populated
// csipmodel.ExtendedDERControlBase.OpModFreqDroop. CSIP CTP v1.3's BASIC-012
// prescribes BOTH halves of its Figure 12 — a frequency-WATT curve and an
// immediate frequency-DROOP control — so the row could be run to half its own
// procedure and no further, and it held itself at FAIL saying exactly that.
// This file is that half of the lever.
//
// ── The element is authored WHOLE or not at all ─────────────────────────────
//
// All five children of FreqDroopType are [1] — IEEE Std 2030.5-2018 p.242 and
// Figure B.37 p.240, which show all five without a cardinality marker. A request
// carrying four of them is REJECTED (400) rather than completed with zeros,
// and the difference is not pedantry: dBOF=0/dBUF=0 is a droop with NO dead
// band and kOF=0/kUF=0 is one with infinite gain — a real and aggressive
// machine, not an absent setting. Silently zero-filling would put a control on
// the wire that commands something nobody asked for, inside documents used to
// certify conformance. (lexa-proto's own csipmodel carried the mirror of this
// defect until 8a65431/R4a: a struct whose four other fields did not exist in
// the schema at all, so a CONFORMANT opModFreqDroop decoded to exactly that
// zero-dead-band machine with no error raised. The correction is what this
// lever emits against.)
//
// ── Units are the standard's own, carried verbatim ─────────────────────────
//
// Per IEEE Std 2030.5-2018 p.242 (and identically in 2030.5-2023 p.269-270 and
// in the vendored draft schema — FreqDroopType is one of the places all three
// documents AGREE element-for-element, type-for-type and unit-for-unit; see
// lexa-proto docs/schema/NORMATIVE_ANCHOR.md §3.5. The citations here were the
// draft's until IW15-027, which made them under-cited rather than wrong):
//
//	dBOF, dBUF     frequency droop dead band, over/under, in THOUSANDTHS of Hz
//	kOF, kUF       per-unit frequency change corresponding to a 1 per-unit
//	               power output change, over/under, in THOUSANDTHS, unitless
//	openLoopTms    open-loop response time in HUNDREDTHS of a second;
//	               0 means "no limit"
//
// Nothing here rescales: a caller states the wire's own units and this server
// serves them. A bench that "helpfully" converted would make the pcap disagree
// with the procedure's own printed test values, which is the one thing the
// evidence may not do.
//
// ── Element ORDER, and the divergence this lever does NOT introduce ─────────
//
// csipmodel.FreqDroop's field order is dBOF, dBUF, kOF, kUF, openLoopTms —
// the XSD's sequence exactly, so the ELEMENT this lever emits is conformant in
// name, type, cardinality and internal order.
//
// Its POSITION inside DERControlBase is not, and that is a PRE-EXISTING
// upstream divergence rather than anything added here. IEEE 2030.5-2018
// declares DERControlBase's twenty-six children in one case-insensitively
// alphabetical sequence (p.248-251: opModConnect, opModEnergize,
// opModFixedPFAbsorbW, opModFixedPFInjectW, opModFixedVar, opModFixedW,
// opModFreqDroop, opModFreqWatt, ... opModWattVar, rampTms).
//
// THE DIVERGENCE THIS PARAGRAPH DESCRIBED IS CLOSED. csipmodel put its struct
// into the standard's sequence (lexa-proto 9856710, re-derived against the
// published document at 13e9106), so OpModFreqDroop now sits between
// OpModFixedW and OpModFreqWatt where "freqd" < "freqw" puts it, rather than
// last. The note survives because a reader of an OLDER pcap from this bench
// will see the old order and should know it was upstream and general. It is
// recorded here because
// a reader of a pcap should know it is upstream and general, and NOT read it
// as a property of the droop lever; fixing it belongs in lexa-proto, in one
// change that reorders the whole struct.

import (
	"fmt"

	model "lexa-proto/csipmodel"
)

// freqDroopReq is the JSON body fragment carrying an opModFreqDroop element,
// shared by POST /admin/control, POST /admin/curve and POST /admin/default.
//
// Every field is a POINTER to a signed int64, and both halves of that are
// deliberate. The pointer distinguishes "absent" from "sent as 0" — 0 is a
// meaningful value for all five (a zero dead band, a zero gain, "no limit") so
// a value-typed field could not tell a caller who omitted an element from one
// who commanded zero. The signed int64 is what lets the range check below
// report an out-of-domain value in the schema's own vocabulary instead of
// leaving encoding/json to answer a negative kOF with "cannot unmarshal number
// -1 into Go value of type uint16", which tells an operator nothing about
// which element or which type.
type freqDroopReq struct {
	DBOF        *int64 `json:"dbof"`          // thousandths of Hz, UInt32
	DBUF        *int64 `json:"dbuf"`          // thousandths of Hz, UInt32
	KOF         *int64 `json:"kof"`           // thousandths, unitless, UInt16
	KUF         *int64 `json:"kuf"`           // thousandths, unitless, UInt16
	OpenLoopTms *int64 `json:"open_loop_tms"` // hundredths of a second, UInt16
}

// freqDroopElement names this element the way the standard and the catalog's
// Figures do, so an error message and a Figure line can be read side by side.
const freqDroopElement = "opModFreqDroop"

// toModel validates the request and renders it into the csipmodel element, or
// returns the reason it cannot be authored.
//
// nil in, nil out: a request that carries no opModFreqDroop at all is not an
// error, it is a control that does not command the axis.
func (r *freqDroopReq) toModel() (*model.FreqDroop, error) {
	if r == nil {
		return nil, nil
	}
	// WHOLE OR NOTHING. See the file doc: all five children are minOccurs="1",
	// and a partial element completed with zeros is a different, aggressive
	// machine rather than a partial command.
	var missing []string
	for _, f := range []struct {
		name string
		v    *int64
	}{
		{"dbof", r.DBOF}, {"dbuf", r.DBUF}, {"kof", r.KOF}, {"kuf", r.KUF},
		{"open_loop_tms", r.OpenLoopTms},
	} {
		if f.v == nil {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s is missing %v: all five children of FreqDroopType are [1] (IEEE Std "+
			"2030.5-2018 p.242), and this server will not complete the element with zeros — a zero dead "+
			"band and "+
			"a zero gain are a real machine, not an absent setting, so a partial request would put a "+
			"control on the wire commanding something the caller never asked for",
			freqDroopElement, missing)
	}
	dbof, err := droopU32("dbof", *r.DBOF)
	if err != nil {
		return nil, err
	}
	dbuf, err := droopU32("dbuf", *r.DBUF)
	if err != nil {
		return nil, err
	}
	kof, err := droopU16("kof", *r.KOF)
	if err != nil {
		return nil, err
	}
	kuf, err := droopU16("kuf", *r.KUF)
	if err != nil {
		return nil, err
	}
	olt, err := droopU16("open_loop_tms", *r.OpenLoopTms)
	if err != nil {
		return nil, err
	}
	return &model.FreqDroop{DBOF: dbof, DBUF: dbuf, KOF: kof, KUF: kuf, OpenLoopTms: olt}, nil
}

// droopU32 range-checks a UInt32 child of FreqDroopType, in the same spirit as
// percentDomainErr (admin.go): a value outside the wire type's domain would
// otherwise wrap into a plausible-looking control the operator never authored,
// and the pcap would then record it as though it had been asked for.
func droopU32(field string, v int64) (uint32, error) {
	if v < 0 || v > 4294967295 {
		return 0, fmt.Errorf("%s.%s %d is outside UInt32's wire domain [0,4294967295] (IEEE Std "+
			"2030.5-2018 p.242, FreqDroopType; the unit is thousandths of Hz)", freqDroopElement, field, v)
	}
	return uint32(v), nil
}

// droopU16 is droopU32 for the three UInt16 children.
func droopU16(field string, v int64) (uint16, error) {
	if v < 0 || v > 65535 {
		return 0, fmt.Errorf("%s.%s %d is outside UInt16's wire domain [0,65535] (IEEE Std 2030.5-2018 "+
			"p.242, FreqDroopType)", freqDroopElement, field, v)
	}
	return uint16(v), nil
}

// adminFreqDroopInfo is what GET /admin/status and GET /admin/default report
// for an authored droop — the same five values, in the same wire units, so an
// inspector shows what is on the wire rather than a re-derived summary.
type adminFreqDroopInfo struct {
	DBOF        uint32 `json:"dbof"`
	DBUF        uint32 `json:"dbuf"`
	KOF         uint16 `json:"kof"`
	KUF         uint16 `json:"kuf"`
	OpenLoopTms uint16 `json:"open_loop_tms"`
}

// freqDroopToInfo renders an authored droop for the admin JSON, or nil when the
// control commands no droop.
func freqDroopToInfo(fd *model.FreqDroop) *adminFreqDroopInfo {
	if fd == nil {
		return nil
	}
	return &adminFreqDroopInfo{
		DBOF: fd.DBOF, DBUF: fd.DBUF, KOF: fd.KOF, KUF: fd.KUF, OpenLoopTms: fd.OpenLoopTms,
	}
}
