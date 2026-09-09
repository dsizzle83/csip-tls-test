package suitessm

// envelope.go is the one seam REV0907-D2-IMPL P5's envelope rows need from
// this package: a REAL, role-bound mbaps session, established exactly the way
// every RBAC-* check in this suite establishes one (checks_rbac.go's
// openRoleSession).
//
// Those rows — suitecsip/localext_envelope.go's EXT-005..008 — measure
// docs/design/AUTHORITY_ENVELOPE_2026-09-08.md's ruling (REV0907-D2-RULING):
// CSIP is the envelope, mbaps may write concurrently but never beyond its
// limits. Their precondition is the CSIP control path owning
// lexa/desired/* (authority.go's AuthorityCSIP family), so they live in
// suitecsip, not here — but the write they issue is a genuine Secure SunSpec
// Modbus write, and this package already owns every line of TLS/PKI/session
// code that knows how to make one. DialEnvelopeRole is the export that lets
// suitecsip reuse it rather than re-implementing a second mbaps client.

import (
	"context"
	"crypto/tls"

	"csip-tls-test/internal/certify"
)

// EnvelopeSession is a role-bound mbaps session opened for an envelope row,
// with the DUT's unit id and discovered SunSpec chain resolved eagerly so a
// caller outside this package never has to reach into its unexported
// chain-walk (discoverChain/findUnit).
type EnvelopeSession struct {
	*Session
	// Unit is the DUT's SunSpec unit id this session discovered its chain on.
	Unit uint8
	// Chain is the discovered model chain, for Chain.Model(id) lookups.
	Chain *Chain
}

// DialEnvelopeRole opens role's certificate fixture (a certs/mbaps stem —
// "grid-service" is what every envelope row uses, matching
// AUTHORITY_ENVELOPE_2026-09-08.md's "an mbaps GridService client") against
// the DUT's mbaps listener over TLS 1.2, the same version every RBAC session
// in this suite pins to, and discovers its SunSpec chain.
//
// skip is non-nil, and sess nil, exactly when this package's own preflight
// (prepare) or role/session/chain resolution failed — a missing -gateway
// target, a missing -pki fixture set, an unreachable DUT, or a DUT whose
// chain this session's role cannot read. The caller returns it as its own
// certify.Result, exactly as every other caller of prepare/roleCert/dial in
// this package already does.
func DialEnvelopeRole(ctx context.Context, rc *certify.RunCtx, role string) (sess *EnvelopeSession, skip *certify.Result) {
	pf, sk := prepare(rc, true)
	if sk != nil {
		return nil, sk
	}
	cert, err := roleCert(pf.PKI, role)
	if err != nil {
		r := certify.Skipped("suitessm: %v", err)
		return nil, &r
	}
	roots, err := rootPool(pf.PKI)
	if err != nil {
		r := certify.Skipped("suitessm: %v", err)
		return nil, &r
	}
	s, err := dial(ctx, rc, pf.Target, dialOpts{
		Cert: cert, Roots: roots,
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		Note: "REV0907-D2-IMPL P5 envelope session: " + role,
	})
	if err != nil {
		r := certify.Failed("suitessm: the %s mbaps session could not be established: %v", role, err)
		return nil, &r
	}
	unit, chain, err := findUnit(rc, s)
	if err != nil {
		s.Close()
		r := certify.Failed("suitessm: could not discover the DUT's SunSpec chain over the %s session: %v",
			role, err)
		return nil, &r
	}
	return &EnvelopeSession{Session: s, Unit: unit, Chain: chain}, nil
}
