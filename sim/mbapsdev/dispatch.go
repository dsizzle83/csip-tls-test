package main

// dispatch.go — the mbap-request server loop over an accepted mbtls.Session:
// mbap.Decode -> dispatch FC 03/06/16 against the register image ->
// mbap.Build*Resp, per T06.3. FC 03/06/16 are routed straight at
// sim.RegisterMap.HandleHoldingRegisters — the SAME method the plain sims'
// real Modbus TCP listener calls (github.com/simonvetter/modbus's server
// dispatch), so every register-level fault (reject_write, nan_sentinel,
// latency, exception_code, unit_id_confusion, register_tearing, …) and the
// scale-factor write-protection (protect.go) apply identically whether the
// request arrived over plain Modbus/TCP (modsim/batsim) or mbaps (mbapsdev).
//
// FC 04 (read input registers) answers exception 01: this bench's SunSpec
// register world is holding-register-only (sim.RegisterMap.HandleInputRegisters
// already returns ErrIllegalFunction unconditionally for the plain sims —
// TASK-021 precedent), so mbapsdev matches rather than inventing a second
// address space no other sim here has.
//
// Frame errors (lexa-proto/mbap's *FrameError contract): the stream is no
// longer trustworthy as frame-aligned after one, so the connection is closed,
// never resynchronized by guessing (CODING_PRINCIPLES §3 MBAP strictness).

import (
	"errors"
	"fmt"
	"io"
	"log"

	modbuslib "github.com/simonvetter/modbus"

	"csip-tls-test/internal/mbtls"
	"lexa-proto/mbap"
)

// dispatchSession serves one accepted mbaps session until a clean close, a
// framing/transport error, or an armed drop_session fault ends it. It always
// runs to completion (never panics on I/O — CODING_PRINCIPLES §1) and closes
// sess on every return path.
func (d *Device) dispatchSession(sess *mbtls.Session) {
	peer := sess.Conn.RemoteAddr().String()
	info := d.sessions.add(sess, peer)
	defer d.sessions.remove(info)
	defer sess.Close()

	role, roleErr := sess.Role()
	if roleErr != nil {
		// mbapsdev does NOT enforce role — AuthZ is the gateway's job
		// (ARCHITECTURE.md §6); the device only demands *a* client cert
		// (mtls.Listen's RequireClientCert). Logged for operator visibility
		// only.
		log.Printf("[mbapsdev] session %s: role extraction: %v (device does not enforce role)", peer, roleErr)
	} else {
		info.setRole(role)
		log.Printf("[mbapsdev] session %s: role=%q cipher=%s tls=%s resumed=%t",
			peer, role, sess.Cipher, sess.TLSVer, sess.Resumed)
	}

	if d.faults.refuseResumeArmed() && sess.Resumed {
		log.Printf("[mbapsdev] session %s: refuse_resume armed and session resumed — closing without serving", peer)
		return
	}

	for {
		adu, err := mbap.Decode(sess.Conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return // clean close between frames
			}
			var fe *mbap.FrameError
			if errors.As(err, &fe) {
				log.Printf("[mbapsdev] session %s: frame error: %v — closing (never resync)", peer, fe)
				return
			}
			log.Printf("[mbapsdev] session %s: read: %v — closing", peer, err)
			return
		}

		if d.faults.dropArmed() {
			log.Printf("[mbapsdev] session %s: drop_session armed — closing mid-exchange (TID %d)", peer, adu.TID)
			return
		}

		info.countRequest()
		resp, err := d.handleADU(adu)
		if err != nil {
			log.Printf("[mbapsdev] session %s: %v — closing", peer, err)
			return
		}
		frame, err := mbap.Encode(resp)
		if err != nil {
			log.Printf("[mbapsdev] session %s: encode response: %v — closing", peer, err)
			return
		}
		if _, err := sess.Conn.Write(frame); err != nil {
			log.Printf("[mbapsdev] session %s: write: %v — closing", peer, err)
			return
		}
	}
}

// handleADU dispatches one decoded request ADU. The returned ADU is always a
// valid response frame (either the real answer or an mbap.Exception) except
// when err is non-nil, which signals a can't-happen shape mbap.Decode should
// already have rejected — callers close the connection on error.
func (d *Device) handleADU(req mbap.ADU) (mbap.ADU, error) {
	if len(req.PDU) == 0 {
		return mbap.ADU{}, fmt.Errorf("mbapsdev: empty pdu (mbap.Decode should reject this)")
	}
	switch req.PDU[0] {
	case mbap.FCReadHolding:
		return d.handleRead(req)
	case mbap.FCReadInput:
		return mbap.Exception(req, mbap.ExIllegalFunction), nil
	case mbap.FCWriteSingle, mbap.FCWriteMultiple:
		return d.handleWrite(req)
	default:
		return mbap.Exception(req, mbap.ExIllegalFunction), nil
	}
}

func (d *Device) handleRead(req mbap.ADU) (mbap.ADU, error) {
	rreq, err := mbap.ParseReadReq(req.PDU)
	if err != nil {
		return exceptionFor(req, err), nil
	}
	values, hErr := d.regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId:   req.UnitID,
		Addr:     rreq.Addr,
		Quantity: rreq.Count,
		IsWrite:  false,
	})
	if hErr != nil {
		return mbap.Exception(req, mapModbusErr(hErr)), nil
	}
	respPDU, err := mbap.BuildReadResp(rreq, values)
	if err != nil {
		return mbap.ADU{}, fmt.Errorf("mbapsdev: build read response: %w", err)
	}
	return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: respPDU}, nil
}

func (d *Device) handleWrite(req mbap.ADU) (mbap.ADU, error) {
	wreq, err := mbap.ParseWriteReq(req.PDU)
	if err != nil {
		return exceptionFor(req, err), nil
	}
	_, hErr := d.regs.HandleHoldingRegisters(&modbuslib.HoldingRegistersRequest{
		UnitId:   req.UnitID,
		Addr:     wreq.Addr,
		Quantity: uint16(len(wreq.Values)),
		IsWrite:  true,
		Args:     wreq.Values,
	})
	if hErr != nil {
		return mbap.Exception(req, mapModbusErr(hErr)), nil
	}
	respPDU, err := mbap.BuildWriteResp(wreq)
	if err != nil {
		return mbap.ADU{}, fmt.Errorf("mbapsdev: build write response: %w", err)
	}
	return mbap.ADU{Header: mbap.Header{TID: req.TID, UnitID: req.UnitID}, PDU: respPDU}, nil
}

// exceptionFor maps a *mbap.PDUError's carried exception code onto the wire.
// Any other error is a can't-happen (mbap.Decode already validated frame
// shape) and answers device-failure rather than silently dropping the
// connection over a parse-layer oddity.
func exceptionFor(req mbap.ADU, err error) mbap.ADU {
	var pe *mbap.PDUError
	if errors.As(err, &pe) {
		return mbap.Exception(req, pe.Ex)
	}
	return mbap.Exception(req, mbap.ExDeviceFailure)
}

// mapModbusErr translates the github.com/simonvetter/modbus sentinel errors
// RegisterMap.HandleHoldingRegisters (and the OnRead fault hooks that feed
// into it) return into the mbap exception code they mean on the wire — the
// exact code mapping design doc 01 §2 assigns (see also
// lexa-proto/mbap.ExCode's own doc comment).
func mapModbusErr(err error) mbap.ExCode {
	switch err {
	case modbuslib.ErrIllegalFunction:
		return mbap.ExIllegalFunction
	case modbuslib.ErrIllegalDataAddress:
		return mbap.ExIllegalAddress
	case modbuslib.ErrIllegalDataValue:
		return mbap.ExIllegalValue
	case modbuslib.ErrServerDeviceBusy:
		return mbap.ExServerBusy
	case modbuslib.ErrGWPathUnavailable:
		return mbap.ExGatewayPath
	case modbuslib.ErrGWTargetFailedToRespond:
		return mbap.ExGatewayTarget
	default: // includes ErrServerDeviceFailure and anything unrecognized
		return mbap.ExDeviceFailure
	}
}
