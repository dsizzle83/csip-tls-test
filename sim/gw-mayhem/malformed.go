package gwmayhem

// malformed.go is the malformed/abusive-write family: an authorized-but-hostile
// aggregator that sends values and frames a well-behaved head-end never would, to
// prove the gateway rejects them cleanly and NEVER applies an out-of-range value to
// a DER. It splits into two scenarios:
//
//   - authz-out-of-range-setpoint — a WMaxLimPct > 100 write. WMaxLimPct is a
//     max-power LIMIT as % of WMax, so a value outside [0,100] is semantically
//     invalid; the gateway's mbaps write decoder now rejects it with exception
//     0x03 and NEVER applies it (lexa-gw internal/writes checkRange, design doc
//     02 §4.4). Expected=PASS. This was PINNED to FAIL while the gap was open
//     (the decoder validated enum/scale/tiling but not numeric range); the fix
//     landed 2026-07-18 and the pin was flipped to PASS the same day.
//
//   - authz-malformed-writes — illegal function code (→ 0x01), oversized PDU (→
//     session closed, no exception leaked), write to a non-existent unit (→ some
//     rejection, never applied), write to a read-only point (→ some rejection).
//     These SHOULD pass against a conformant gateway (Expected=PASS).
//
// The illegal-FC and oversized-PDU probes need raw MBAP framing over the decrypted
// session (the aggregator's typed client only speaks FC 03/04/06/16), so they are
// Go-literal, not data.

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/mbap"
	"lexa-proto/sunspec"
)

// outOfRangePct is the hostile setpoint: 150% active-power limit, well past the
// 100% ceiling a WMaxLimPct can logically carry.
const outOfRangePct = 150

// outOfRangeSetpoint builds the out-of-range-setpoint scenario: a GridService
// commanding WMaxLimPct=150 must be rejected (0x03) and never applied.
func outOfRangeSetpoint() gwScenario {
	return gwScenario{
		ID:       "authz-out-of-range-setpoint",
		Desc:     "GridService writes WMaxLimPct=150 — must be rejected (0x03), NEVER applied",
		Category: "mbaps-northbound-authz",
		Source:   SourceGo,
		Security: true,
		// Was PINNED FAIL while the gateway accepted out-of-range setpoints (no
		// mbaps-layer range check); the fix (internal/writes checkRange) landed
		// 2026-07-18 and the pin was flipped to PASS.
		Expected: []Verdict{VerdictPass},
		arm:      armOutOfRange,
		oracle:   "malformedWrite",
	}
}

// armOutOfRange writes an out-of-range WMaxLimPct as a role that IS allowed to
// write controls (GridService), isolating the value check from the authz check.
func armOutOfRange(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		ev.SetupErr = "no control unit (704) to write"
		return nil
	}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		ev.SetupErr = "connect GridService: " + err.Error()
		return nil
	}
	defer conn.Close()

	wo := writeOutcome{Name: "out-of-range-wmaxlimpct-150", ExpectRejectCode: uint8(mbap.ExIllegalValue)}
	res, perr := conn.ProbeDenied(unit, sunspec.ModelDERCtlAC, matrixCtrlPoint, outOfRangePct)
	switch {
	case perr != nil:
		wo.TransportErr = perr.Error()
	case res.Wrote:
		wo.Accepted = true
		wo.Note = "gateway returned write-success for WMaxLimPct=150 (no range check — design §4.4 gap)"
	default:
		wo.ExCode = res.ExceptionCode
	}
	ev.Writes = append(ev.Writes, wo)
	return nil
}

// malformedWrites builds the clean-rejection scenario.
func malformedWrites() gwScenario {
	return gwScenario{
		ID:       "authz-malformed-writes",
		Desc:     "illegal FC → 0x01; oversized PDU → session closed; nonexistent unit + read-only point → rejected, never applied",
		Category: "mbaps-northbound-authz",
		Source:   SourceGo,
		Security: true,
		Expected: []Verdict{VerdictPass},
		arm:      armMalformedWrites,
		oracle:   "malformedWrite",
	}
}

func armMalformedWrites(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, _, ok := w.discoverControlUnit(ctx)
	if !ok {
		ev.SetupErr = "no control unit (704) to probe"
		return nil
	}
	ev.Writes = append(ev.Writes, probeIllegalFC(ctx, w, unit))
	ev.Writes = append(ev.Writes, probeOversizedPDU(ctx, w, unit))
	ev.Writes = append(ev.Writes, probeNonexistentUnit(ctx, w))
	ev.Writes = append(ev.Writes, probeReadOnlyPoint(ctx, w, unit))
	return nil
}

// probeIllegalFC sends a raw frame with an unsupported function code (0x2B,
// Encapsulated Interface Transport) as GridService and expects exception 0x01
// (the gateway's FC map answers every non-03/04/06/16 FC with 0x01, before any
// role/unit check).
func probeIllegalFC(ctx context.Context, w *gwWorld, unit uint8) writeOutcome {
	wo := writeOutcome{Name: "illegal-function-code", ExpectRejectCode: uint8(mbap.ExIllegalFunction)}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		wo.TransportErr = "connect: " + err.Error()
		return wo
	}
	defer conn.Close()
	code, isEx, closed, xerr := rawExchange(conn, []byte{0x2B, 0x0E, 0x01, 0x00}, unit)
	switch {
	case closed:
		wo.SessionClosed = true
		wo.Note = "session closed on an illegal FC (expected a bare 0x01 exception)"
	case xerr != nil:
		wo.TransportErr = xerr.Error()
	case isEx:
		wo.ExCode = code
	default:
		wo.Accepted = true
		wo.Note = "illegal FC 0x2B got a non-exception response"
	}
	return wo
}

// probeOversizedPDU sends a raw MBAP header whose Length field claims a body far
// past the 253-byte PDU cap. A conformant gateway rejects it as a framing
// violation and CLOSES the session (never a resync, never an exception PDU).
func probeOversizedPDU(ctx context.Context, w *gwWorld, unit uint8) writeOutcome {
	wo := writeOutcome{Name: "oversized-pdu", ExpectSessionClosed: true}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		wo.TransportErr = "connect: " + err.Error()
		return wo
	}
	defer conn.Close()
	sess := conn.Session()
	if sess == nil || sess.Conn == nil {
		wo.TransportErr = "no live session"
		return wo
	}
	c := sess.Conn
	// Hand-built frame: mbap.Encode caps the PDU at 253, so bypass it. Length=400
	// is out of the strict [3,254] range; the gateway's Decode rejects at the length
	// check before reading any body, so a 7-byte header suffices.
	var hdr [7]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x4243) // TID
	// hdr[2:4] PID stays 0.
	binary.BigEndian.PutUint16(hdr[4:6], 400) // illegal Length
	hdr[6] = unit
	_ = c.SetDeadline(time.Now().Add(rawOpDeadline))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, werr := c.Write(hdr[:]); werr != nil {
		wo.TransportErr = "write: " + werr.Error()
		return wo
	}
	resp, derr := mbap.Decode(c)
	switch {
	case derr != nil:
		wo.SessionClosed = true // torn down as required (EOF / frame error / reset)
		wo.Note = "gateway closed the session: " + firstLine(derr.Error())
	case len(resp.PDU) >= 2 && resp.PDU[0]&0x80 != 0:
		wo.ExCode = resp.PDU[1]
		wo.Note = "gateway answered an oversized frame with an exception instead of closing"
	default:
		wo.Accepted = true
		wo.Note = "gateway answered an oversized frame with a normal response"
	}
	return wo
}

// probeNonexistentUnit writes a control to an unmapped unit as GridService. The
// gateway must reject it (0x01 if the role has no standing for that unit, or 0x0A
// if authz passes but the unit is unknown) and never apply it.
func probeNonexistentUnit(ctx context.Context, w *gwWorld) writeOutcome {
	wo := writeOutcome{Name: "write-nonexistent-unit", AnyRejectOK: true, Note: "unit 200 (unmapped)"}
	conn, err := w.connectAsReady(ctx, aggregator.RoleGridService)
	if err != nil {
		wo.TransportErr = "connect: " + err.Error()
		return wo
	}
	defer conn.Close()
	res, perr := conn.ProbeDenied(200, sunspec.ModelDERCtlAC, matrixCtrlPoint, matrixNominalPct)
	switch {
	case perr != nil:
		wo.TransportErr = perr.Error()
	case res.Wrote:
		wo.Accepted = true
	default:
		wo.ExCode = res.ExceptionCode
	}
	return wo
}

// probeReadOnlyPoint writes to the read-only SunSpec base marker as SuperAdmin
// (whose rw* grant passes authz), so only the write decoder's defense-in-depth can
// refuse it. The security property is non-application (some rejection), not a
// specific code.
func probeReadOnlyPoint(ctx context.Context, w *gwWorld, unit uint8) writeOutcome {
	wo := writeOutcome{Name: "write-read-only-point", AnyRejectOK: true, Note: "SunSpec base marker (read-only)"}
	conn, err := w.connectAsReady(ctx, aggregator.RoleSuperAdmin)
	if err != nil {
		wo.TransportErr = "connect: " + err.Error()
		return wo
	}
	defer conn.Close()
	// Raw FC16 to the read-only SunSpec identifier registers.
	werr := conn.WriteMultiple(unit, sunspec.SunSpecBase, []uint16{0x5375, 0x6e53})
	switch {
	case werr == nil:
		wo.Accepted = true
	default:
		if code, isEx := exCode(werr); isEx {
			wo.ExCode = code
		} else {
			wo.TransportErr = werr.Error()
		}
	}
	return wo
}

// rawOpDeadline bounds a raw-frame exchange so a wedged peer cannot hang a probe.
const rawOpDeadline = 6 * time.Second

// rawExchange writes a raw PDU over the decrypted session and reads one response
// frame, reporting the exception code (if any), whether the session was closed, and
// any transport error. It uses the session's net.Conn directly — the aggregator's
// typed client cannot express an arbitrary function code.
func rawExchange(conn *aggregator.Conn, pdu []byte, unit uint8) (code uint8, isEx, closed bool, err error) {
	sess := conn.Session()
	if sess == nil || sess.Conn == nil {
		return 0, false, false, fmt.Errorf("no live session")
	}
	c := sess.Conn
	frame, encErr := mbap.Encode(mbap.ADU{Header: mbap.Header{TID: 0x4242, UnitID: unit}, PDU: pdu})
	if encErr != nil {
		return 0, false, false, encErr
	}
	_ = c.SetDeadline(time.Now().Add(rawOpDeadline))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, werr := c.Write(frame); werr != nil {
		return 0, false, false, werr
	}
	resp, derr := mbap.Decode(c)
	if derr != nil {
		return 0, false, true, derr // torn down (EOF / frame error)
	}
	if len(resp.PDU) >= 2 && resp.PDU[0]&0x80 != 0 {
		return resp.PDU[1], true, false, nil
	}
	return 0, false, false, nil
}
