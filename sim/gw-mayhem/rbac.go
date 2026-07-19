package gwmayhem

// rbac.go is the RBAC CONTRACT the mbaps-northbound-authz family judges the
// gateway against — the grant/deny matrix lexa-gw's authz engine actually
// enforces (internal/authz over configs/rbac/rules.json + the base mbaps-mode
// overlays), transcribed here as a Go table so the role-denial-matrix oracle is a
// pure function over data, not a re-derivation of the product's config. It is the
// bench's OWN independent statement of the expected matrix (referee independence,
// C9): if the gateway's compiled matrix ever diverges from this table, THAT is the
// finding — the QA must not import the gateway's own rules to check the gateway.
//
// Scope: the SHIPPED DEFAULT authority mode (`authority=mbaps`, `vendor_access=true`)
// — the mode the live bench gateway runs. The csip/local overlays (which strip
// write from GridService/Super, or make every privileged role read-only) are a
// NEXT-WAVE family (authority/PKI/infra); pinning them needs the gateway put into
// those modes, a board-mutating step out of scope for wave 1.

import "sort"

// opClass names the three operation classes the matrix sweeps. They map to Modbus
// function codes + register regions the gateway authorizes: reads of measurement
// models (701 and friends) vs reads of the control model (704 commanded points)
// vs writes of the control model.
type opClass string

const (
	opReadMeas opClass = "read-meas" // FC03/04 read of a measurement model (701)
	opReadCtl  opClass = "read-ctl"  // FC03/04 read of the control model (704)
	opWriteCtl opClass = "write-ctl" // FC16 write of a commanded control point (704 WMaxLimPct)
)

// opClasses is the sweep order (reads first, then the write — so a role that is
// wrongly denied a legitimate read is reported before the louder write gap).
func opClasses() []opClass { return []opClass{opReadMeas, opReadCtl, opWriteCtl} }

// grant is the expected authz outcome for one role×op cell.
type grant string

const (
	grantAllow grant = "grant" // the gateway MUST permit this op for this role
	grantDeny  grant = "deny"  // the gateway MUST reject it with exception 0x01
)

// rbacContract is the base-mode grant/deny matrix (role → op → expected outcome),
// per lexa-gw's rules.json + the mbaps-mode compilation:
//
//   - ReadOnlySunSpec / LexaVoltReadOnly: read everything, write nothing.
//   - GridServiceSunSpec: read everything; write the `commanded` group on 704-712.
//   - NetworkAdministratorSunSpec: read everything; its only write grant is the
//     `net-admin` point group, which is DELIBERATELY EMPTY in v1 — so it resolves
//     to ZERO writable registers and a control write is DENIED. This is the
//     non-obvious cell the matrix exists to pin: "admin" does NOT imply "can write
//     controls".
//   - SuperAdministratorSunSpec: read + write everything (rw *).
//
// Every role reads both measurement and control points (the base `r *` grant), so
// only the write-ctl column differs across roles.
var rbacContract = map[string]map[opClass]grant{
	"ReadOnlySunSpec": {
		opReadMeas: grantAllow, opReadCtl: grantAllow, opWriteCtl: grantDeny,
	},
	"LexaVoltReadOnly": {
		opReadMeas: grantAllow, opReadCtl: grantAllow, opWriteCtl: grantDeny,
	},
	"GridServiceSunSpec": {
		opReadMeas: grantAllow, opReadCtl: grantAllow, opWriteCtl: grantAllow,
	},
	"NetworkAdministratorSunSpec": {
		opReadMeas: grantAllow, opReadCtl: grantAllow, opWriteCtl: grantDeny,
	},
	"SuperAdministratorSunSpec": {
		opReadMeas: grantAllow, opReadCtl: grantAllow, opWriteCtl: grantAllow,
	},
}

// expectedGrant returns the contract outcome for role×op, and whether the pair is
// covered by the contract at all (an unknown role is a coverage gap, not a silent
// grant).
func expectedGrant(role string, op opClass) (grant, bool) {
	ops, ok := rbacContract[role]
	if !ok {
		return "", false
	}
	g, ok := ops[op]
	return g, ok
}

// contractRoles returns the roles the contract covers, in a stable order.
func contractRoles() []string {
	out := make([]string, 0, len(rbacContract))
	for r := range rbacContract {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
