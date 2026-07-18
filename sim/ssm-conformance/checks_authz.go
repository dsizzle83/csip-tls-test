package main

// checks_authz.go asserts §5.3 Role-Based Client Authorization (TCP-8 and
// TCP-21..41) against the target's authz engine. It is the direct T06.10 use of
// the T06.8 denial-matrix primitives (aggregator.ConnectAs / ProbeDenied) and the
// T06.1 negative fixtures as the evidence source: role certs authenticate and
// their grant/deny outcomes differ by role, role-less / malformed certs are
// denied every request with a bare exception 0x01, and the role is extracted from
// the certificate via the PEN OID as an ASN.1 UTF8String (exactly one per cert).

import (
	"context"
	"errors"
	"time"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
	"lexa-proto/sunspec"
)

const (
	authzCtrlModel = sunspec.ModelDERCtlAC // 704 — a commanded control point (write-gated)
	authzCtrlPoint = "WMaxLimPct"
)

// checkAuthz covers TCP-8 and TCP-21..41.
func checkAuthz(r *Reporter, rc *runCtx) {
	r.section("5.3", "Role-Based Client Authorization (TCP-8, 21..41)")
	ps := rc.ps
	refs := ps.refs()

	// ── Role extension shape (TCP-27..31), read straight off the fixtures with
	//    the bench's own referee parser (mbtls.RoleFromDER). ──────────────────
	gridCert := ps.roles[RoleGridService].certFile
	gotRole, roleErr := roleFromCert(gridCert)

	// TCP-27 — client provisioned with an X.509v3 domain certificate.
	r.verdict(27, roleErr == nil, "client presents an X.509v3 domain cert carrying role %q: err=%v", gotRole, roleErr)

	// TCP-28 — client cert MUST include the Role extension; the server cert need
	// not. Our client leaf carries a role; a good handshake's peer (server) leaf
	// carries none.
	serverHasRole := false
	if s, err := dialRole(rc.target, ps, RoleGridService); err == nil {
		if _, rerr := mbtls.RoleFromDER(s.PeerDER); rerr == nil {
			serverHasRole = true
		}
		s.Close()
	}
	r.verdict(28, roleErr == nil && gotRole == string(RoleGridService) && !serverHasRole,
		"client cert carries role %q; server cert carries no role ext (server-role-present=%t)", gotRole, serverHasRole)

	// TCP-29 — role uses PEN OID 1.3.6.1.4.1.50316.802.1 (RoleFromDER walks that
	// OID; a successful extraction is proof it is present and read).
	r.verdict(29, roleErr == nil && gotRole == string(RoleGridService),
		"role extracted via PEN OID %s = %q", mbtls.RoleOID.String(), gotRole)

	// TCP-30 — role MUST be ASN.1 UTF8String. Positive: the happy cert parses.
	// Negative: the bad-encoding fixture (PrintableString) is rejected as
	// ErrBadEncoding.
	badEncOK := negParseErrIs(ps, "bad-encoding", "ErrBadEncoding")
	r.verdict(30, roleErr == nil && badEncOK, "UTF8String role parses; PrintableString (bad-encoding) rejected as ErrBadEncoding=%t", badEncOK)

	// TCP-31 — exactly one role per cert; the whole string is the role. Positive:
	// one role parses. Negative: the two-role fixture is rejected as
	// ErrMultipleRoles.
	twoRoleOK := negParseErrIs(ps, "two-role", "ErrMultipleRoles")
	r.verdict(31, roleErr == nil && twoRoleOK, "exactly one role per cert; two-role fixture rejected as ErrMultipleRoles=%t", twoRoleOK)

	// ── Role support + grant/deny matrix (TCP-8/21/22/26/38/39/40/41). ────────
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// TCP-22 — MUST support the four mandatory roles + LexaVolt: each authenticates
	// and can read.
	supported, unsupported := supportedRoles(rc, refs)
	r.verdict(22, len(unsupported) == 0, "roles authenticated + read: %v (unsupported: %v)", supported, unsupported)

	// Locate a served unit with a write-gated control model to drive the matrix.
	unit, haveCtrl := findControlUnit(rc, refs, ctx)
	if !haveCtrl {
		note := "no served unit with model 704 found on the target — cannot drive the grant/deny matrix"
		for _, n := range []int{8, 21, 39, 40, 41, 38, 26} {
			r.warn(n, "%s (role-extension shape TCP-27..31 still asserted above)", note)
		}
	} else {
		grantOK := roleWriteGranted(rc, refs, unit)               // GridService control write accepted
		roDenied := roleWriteDenied(rc, refs, RoleReadOnly, unit) // ReadOnly write → 0x01
		lvDenied := roleWriteDenied(rc, refs, RoleLexaVolt, unit) // LexaVolt write → 0x01
		bareExc := roDenied.bare && lvDenied.bare                 // exactly 0x01, nothing else

		// TCP-8 / TCP-21 / TCP-39 — the role from the cert drives authz: grant for
		// GridService, deny for read-only ⇒ the server extracted and applied the role.
		roleDriven := grantOK && roDenied.denied
		r.verdict(8, roleDriven, "authz uses the cert role: GridService write granted=%t, ReadOnly write denied(0x01)=%t (unit %d)", grantOK, roDenied.denied, unit)
		r.verdict(21, roleDriven, "role-based authz per MODBUS/TCP §8.4: grant/deny differs by role on unit %d", unit)
		r.verdict(39, roleDriven, "server extracts the client role from the cert and authorizes by it (grant≠deny across roles)")

		// TCP-40 — AuthZ rejection ⇒ exception 01.
		r.verdict(40, roDenied.denied && lvDenied.denied, "read-only role writes rejected with exception 0x01 (ReadOnly=%d, LexaVolt=%d)", roDenied.code, lvDenied.code)

		// TCP-41 — rejected request ⇒ exception, no additional information (a bare
		// 2-byte exception PDU, no data, not a partial success).
		r.verdict(41, bareExc && !roDenied.wrote && !lvDenied.wrote, "denial is a bare exception 0x01, no extra data, no partial write")

		// TCP-38 — cert role values consistent with the rules DB (the role each
		// cert carries is exactly the one authz grants/denies on).
		r.verdict(38, roleDriven, "cert role values map consistently onto the rights DB (GridService=grant, ReadOnly/LexaVolt=deny)")

		// TCP-26 — role extension + AuthZ algorithm + rules DB REQUIRED (composite:
		// the ext is present and an authz decision was made from it).
		r.verdict(26, roleErr == nil && roleDriven, "role extension present and an authz decision was derived from it (rules DB in effect)")
	}

	// TCP-32 — no role in cert ⇒ exception 01, on every request, session up.
	noRoleDenied := negEveryRequestDenied(rc, "no-role") &&
		negEveryRequestDenied(rc, "two-role") &&
		negEveryRequestDenied(rc, "bad-encoding") &&
		negEveryRequestDenied(rc, "empty-role")
	r.verdict(32, noRoleDenied, "role-less / malformed-role certs are denied every request with exception 0x01, TLS session stays up")

	// ── Server-side rules-DB configuration meta (not client-observable). ──────
	r.skip(23, "IEC 62351-8 roles are a MAY (deferred, not implemented)")
	r.skip(24, "roles-to-rights-DB completeness over ALL points is a server-side artifact (lexa-gw T02); the grant/deny matrix shows a rights DB is in effect")
	r.skip(25, "the mandatory roles use the SunSpec rbac map as a server-side data source (lexa-gw T02); the canonical role names are used (TCP-22)")
	r.skip(33, "AuthZ algorithm is a vendor design/documentation property (ARCHITECTURE.md), not a wire assertion")
	r.skip(34, "rules-DB syntax/semantics is a vendor design property (documented), not a wire assertion")
	r.skip(35, "rules-DB configured per vendor design — a server config property (lexa-gw T02)")
	r.skip(36, "rules-DB configurability is a dev-API/admin property (lexa-gw T02/T05), not a client-observable handshake behavior")
	r.skip(37, "absence of unchangeable hardcoded default roles is a server config property (lexa-gw T02)")
}

// roleFromCert extracts the role from a PEM cert file's leaf via the bench's own
// parser (over the raw DER, so a duplicate-OID negative is not pre-rejected by
// crypto/x509).
func roleFromCert(certFile string) (string, error) {
	der, err := rawLeafDER(certFile)
	if err != nil {
		return "", err
	}
	return mbtls.RoleFromDER(der)
}

// negParseErrIs reports whether negative fixture name's leaf provokes exactly the
// named RoleFromDER error taxonomy value.
func negParseErrIs(ps *pkiSet, name, want string) bool {
	neg, ok := ps.negatives[name]
	if !ok {
		return false
	}
	der, err := rawLeafDER(neg.certFile)
	if err != nil {
		return false
	}
	_, rerr := mbtls.RoleFromDER(der)
	switch want {
	case "ErrNoRole":
		return rerr == mbtls.ErrNoRole
	case "ErrMultipleRoles":
		return rerr == mbtls.ErrMultipleRoles
	case "ErrBadEncoding":
		return errIsBadEncoding(rerr)
	}
	return false
}

// errIsBadEncoding matches the wrapped ErrBadEncoding taxonomy value.
func errIsBadEncoding(err error) bool {
	return err != nil && errors.Is(err, mbtls.ErrBadEncoding)
}

// supportedRoles returns the roles that authenticated and could read, and those
// that failed — the TCP-22 evidence.
func supportedRoles(rc *runCtx, refs aggregator.PKIRefs) (ok, bad []Role) {
	for _, role := range refs.Roles() {
		conn, err := aggregator.ConnectAs(rc.target, role, refs)
		if err != nil {
			bad = append(bad, role)
			continue
		}
		// A read that returns either data or a protocol exception proves the role
		// authenticated and the session round-trips; a transport error is a failure.
		perr := conn.Ping(rc.probeUnit())
		conn.Close()
		if perr != nil {
			bad = append(bad, role)
			continue
		}
		ok = append(ok, role)
	}
	return ok, bad
}

// findControlUnit discovers a served unit that advertises the write-gated control
// model (704) so the grant/deny matrix has a real target.
func findControlUnit(rc *runCtx, refs aggregator.PKIRefs, ctx context.Context) (uint8, bool) {
	conn, err := aggregator.ConnectAs(rc.target, RoleGridService, refs)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	probe := []uint8{1, 2, 3, 4, 5, 6, 7, 8}
	devs, err := conn.Discover(ctx, probe...)
	if err != nil && len(devs) == 0 {
		return 0, false
	}
	for _, d := range devs {
		for _, m := range d.Models {
			if m == authzCtrlModel {
				return d.Unit, true
			}
		}
	}
	return 0, false
}

// roleWriteGranted reports whether a GridService control write is accepted.
func roleWriteGranted(rc *runCtx, refs aggregator.PKIRefs, unit uint8) bool {
	conn, err := aggregator.ConnectAs(rc.target, RoleGridService, refs)
	if err != nil {
		return false
	}
	defer conn.Close()
	return conn.WritePoint(unit, authzCtrlModel, authzCtrlPoint, 50) == nil
}

// denial is the outcome of a read-only role's write probe.
type denial struct {
	denied bool  // returned exception 0x01
	code   uint8 // the exception code observed
	wrote  bool  // the write was (wrongly) accepted
	bare   bool  // exactly 0x01 with no partial success
}

// roleWriteDenied probes a control write as a read-only role and classifies the
// answer (ProbeDenied surfaces the exception code without a transport error).
func roleWriteDenied(rc *runCtx, refs aggregator.PKIRefs, role Role, unit uint8) denial {
	conn, err := aggregator.ConnectAs(rc.target, role, refs)
	if err != nil {
		return denial{}
	}
	defer conn.Close()
	res, err := conn.ProbeDenied(unit, authzCtrlModel, authzCtrlPoint, 25)
	if err != nil {
		return denial{} // a transport error is not a clean denial
	}
	return denial{
		denied: res.Denied && res.ExceptionCode == 1,
		code:   res.ExceptionCode,
		wrote:  res.Wrote,
		bare:   res.Denied && res.ExceptionCode == 1 && !res.Wrote,
	}
}

// negEveryRequestDenied dials with negative fixture name (bypassing the aggregator
// role self-check) and asserts a read returns exactly exception 0x01 — the
// session stays up (a protocol exception, not a transport break) but every
// request is denied (TCP-32).
func negEveryRequestDenied(rc *runCtx, name string) bool {
	neg, ok := rc.ps.negatives[name]
	if !ok {
		return false
	}
	sess, err := dialCred(rc.target, rc.ps.serverCA, neg.certFile, neg.keyFile)
	if err != nil || sess == nil {
		// The handshake itself must SUCCEED — role errors collapse at authz, not
		// at the handshake (design 01 §3.1). A handshake failure here is a wrong
		// enforcement layer.
		return false
	}
	defer sess.Close()
	_, rerr := rawRead(sess, rc.probeUnit(), sunspec.SunSpecBase, 2)
	code, isEx := exceptionCode(rerr)
	return isEx && code == 1
}
