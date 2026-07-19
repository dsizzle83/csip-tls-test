package gwmayhem

// matrix.go is the role-denial MATRIX — the headline security scenario. As each
// role in the PKI it drives one cell per operation class (read a measurement model,
// read the control model, write the control model) against a served control unit
// and records the gateway's grant/deny, then diagnoseAuthzMatrix asserts every
// cell matches the RBAC contract (rbac.go). This is where a read-only role that
// gets a write ACK, an "admin" role that can write a control it must not
// (NetworkAdmin), or a grid-service role denied a legitimate read, becomes a FAIL.
//
// It is a Go-literal scenario, not a data campaign: the sweep is real logic
// (roles × ops, each cell's expected outcome looked up from the contract table),
// exactly the "needs logic ⇒ stays Go" boundary.

import (
	"context"
	"fmt"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/sunspec"
)

// matrixCtrlPoint is the commanded control point the matrix reads/writes on model
// 704; matrixMeasPoint is a measurement point on 701. matrixNominalPct is the
// benign value a GRANT-write cell writes — 100% = no curtailment, so a granted
// write never leaves a DER limited (the aggregator is a pure control client; a
// nominal WMaxLimPct is its normal traffic, not a board-mutating step).
const (
	matrixCtrlModel  = sunspec.ModelDERCtlAC     // 704
	matrixMeasModel  = sunspec.ModelDERMeasureAC // 701
	matrixCtrlPoint  = "WMaxLimPct"
	matrixMeasPoint  = "W"
	matrixNominalPct = 100
)

// roleDenialMatrix builds the headline matrix scenario.
func roleDenialMatrix() gwScenario {
	return gwScenario{
		ID:       "authz-role-denial-matrix",
		Desc:     "RBAC grant/deny matrix: every role × {read-meas, read-ctl, write-ctl} matches the contract",
		Category: "mbaps-northbound-authz",
		Source:   SourceGo,
		Security: true,
		Expected: []Verdict{VerdictPass},
		arm:      armRoleDenialMatrix,
		oracle:   "authzMatrix",
	}
}

// armRoleDenialMatrix discovers a control unit, detects the vendor-access mode, then
// sweeps every contract role × op class, recording one authzCell per cell. A
// discovery failure is a setup error (INCONCLUSIVE), not a gateway verdict.
func armRoleDenialMatrix(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	unit, hasMeas, ok := w.discoverControlUnit(ctx)
	if !ok {
		ev.SetupErr = "no served unit advertises the control model (704) — cannot drive the matrix"
		return nil
	}
	// The base RBAC contract assumes vendor_access=true; a gateway with
	// vendor_access=false DELETES LexaVoltReadOnly (30-vendor-disabled overlay), so
	// that role is denied EVERY op. Detect the mode so the LexaVolt row is judged
	// against the deployed reality, not a fixed assumption — while a REAL bug (a
	// disabled role that can still write, or a non-vendor role diverging) is still a
	// FAIL.
	vendorDisabled := probeVendorDisabled(w, unit)
	if vendorDisabled {
		ev.MatrixMode = "vendor_access=false (LexaVoltReadOnly deleted → denied every op)"
	} else {
		ev.MatrixMode = "vendor_access=true (LexaVoltReadOnly active, read-only)"
	}

	for _, role := range w.roles() {
		if _, covered := rbacContract[string(role)]; !covered {
			continue // a PKI role the contract does not describe — skip (coverage is the contract's)
		}
		conn, err := w.connectAs(role)
		if err != nil {
			// The role could not even connect — every cell for it is unobservable.
			for _, op := range opClasses() {
				ev.Cells = append(ev.Cells, authzCell{
					Role: string(role), Op: op, Unit: unit, Expected: matrixExpected(string(role), op, vendorDisabled),
					Outcome: "error", Note: fmt.Sprintf("connect failed: %v", err),
				})
			}
			continue
		}
		for _, op := range opClasses() {
			ev.Cells = append(ev.Cells, probeCell(conn, role, op, unit, hasMeas, vendorDisabled))
		}
		conn.Close()
	}
	return nil
}

// probeVendorDisabled reports whether the target runs vendor_access=false, detected
// by LexaVoltReadOnly being denied a plain read (its role is deleted, so even reads
// answer 0x01). A granted/absent-error read means the role is active (vendor_access
// =true). A connect or transport failure conservatively reports "not disabled" so a
// transient error never silently flips the whole LexaVolt row to "deny expected".
func probeVendorDisabled(w *gwWorld, unit uint8) bool {
	conn, err := w.connectAs(aggregator.RoleLexaVolt)
	if err != nil {
		return false
	}
	defer conn.Close()
	_, rerr := conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint)
	if ex, ok := aggregator.AsException(rerr); ok && uint8(ex.Code) == 0x01 {
		return true
	}
	return false
}

// matrixExpected is the contract's expected grant/deny for role×op, adjusted for the
// detected vendor-access mode: with vendor_access=false, LexaVoltReadOnly is deleted
// and every op is denied.
func matrixExpected(role string, op opClass, vendorDisabled bool) grant {
	if role == string(aggregator.RoleLexaVolt) && vendorDisabled {
		return grantDeny
	}
	g, _ := expectedGrant(role, op)
	return g
}

// probeCell drives one role×op cell and classifies the gateway's answer against the
// mode-adjusted contract's expected grant/deny.
func probeCell(conn *aggregator.Conn, role aggregator.Role, op opClass, unit uint8, hasMeas, vendorDisabled bool) authzCell {
	cell := authzCell{Role: string(role), Op: op, Unit: unit, Expected: matrixExpected(string(role), op, vendorDisabled)}
	switch op {
	case opReadMeas:
		if !hasMeas {
			cell.Outcome = "error"
			cell.Note = "unit has no measurement model (701) to probe"
			return cell
		}
		classifyRead(conn.ReadPoint(unit, matrixMeasModel, matrixMeasPoint))(&cell)
	case opReadCtl:
		classifyRead(conn.ReadPoint(unit, matrixCtrlModel, matrixCtrlPoint))(&cell)
	case opWriteCtl:
		res, err := conn.ProbeDenied(unit, matrixCtrlModel, matrixCtrlPoint, matrixNominalPct)
		switch {
		case err != nil:
			cell.Outcome = "error"
			cell.Note = "transport error: " + err.Error()
		case res.Wrote:
			cell.Outcome = "granted"
			cell.Wrote = true
			cell.Note = fmt.Sprintf("write %s=%d accepted", matrixCtrlPoint, matrixNominalPct)
		default:
			cell.Outcome = "denied"
			cell.ExCode = res.ExceptionCode
		}
	}
	return cell
}

// classifyRead maps a ReadPoint result to an authzCell mutation: a value (even a
// NaN sentinel — the point is present but N/A) or a non-authz exception means the
// read REACHED the data layer (granted); exception 0x01 is an authz denial; a
// transport failure is an error.
func classifyRead(_ float64, err error) func(*authzCell) {
	return func(cell *authzCell) {
		if err == nil {
			cell.Outcome = "granted"
			return
		}
		if ex, ok := aggregator.AsException(err); ok {
			if uint8(ex.Code) == 0x01 {
				cell.Outcome = "denied"
				cell.ExCode = 0x01
				return
			}
			cell.Outcome = "granted"
			cell.ExCode = uint8(ex.Code)
			cell.Note = fmt.Sprintf("reached data layer (exception 0x%02x, not an authz denial)", ex.Code)
			return
		}
		cell.Outcome = "error"
		cell.Note = "transport error: " + err.Error()
	}
}
