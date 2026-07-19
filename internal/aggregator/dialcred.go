package aggregator

// dialcred.go adds the RAW-CREDENTIAL connect primitive the hostile-QA layer
// (sim/gw-mayhem) needs to present a DELIBERATELY WRONG or role-less client
// certificate — the cert-authz negative fixtures (no-role / two-role / malformed
// / empty / oversize / expired / wrong-CA). It is the Conn-returning sibling of
// ssm-conformance's dialCred (sim/ssm-conformance/probe.go): where ConnectAs
// self-checks that the presented cert actually carries the intended role (a guard
// against a mis-wired manifest), ConnectCred SKIPS that check on purpose — the
// whole point of a negative fixture is to hand the gateway a cert whose asserted
// role differs from (or is absent in) the leaf, and to observe where the failure
// lands: at the TLS handshake (expired / wrong-CA) or at the authz layer
// (role-less / malformed → exception 0x01, session up). It shares nothing new
// with the product: it dials over the bench's own mbtls glue and returns the same
// *Conn the rest of the driver uses, so Ping / ProbeDenied / ReadHolding work
// unchanged over a hostile session.

import (
	"fmt"

	"csip-tls-test/internal/mbtls"
	"lexa-proto/sunspec"
)

// ConnectCred dials addr presenting the leaf chain + key at certFile/keyFile,
// verifying the peer's SERVER certificate against serverCA, and returns a live
// *Conn. Unlike ConnectAs it performs NO role self-check: certFile may carry any
// role, an empty/oversize role, or none at all. assertedRole is recorded on the
// session facts for the report (the role the adversary CLAIMS to be, if any); it
// does not gate the dial. A handshake failure (expired cert, wrong CA, no key) is
// returned as an error — that is itself the evidence a cert-authz scenario judges
// (handshake-layer rejection vs authz-layer denial).
func ConnectCred(addr, serverCA, certFile, keyFile, assertedRole string) (*Conn, error) {
	if serverCA == "" {
		return nil, fmt.Errorf("aggregator: ConnectCred needs a ServerCA to verify the peer")
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("aggregator: ConnectCred needs a client cert + key (got cert=%q key=%q)", certFile, keyFile)
	}
	profile := mbtls.DefaultClientProfile(serverCA, certFile, keyFile)
	profile.RoleAsserted = assertedRole

	c := &Conn{
		addr:      addr,
		role:      Role(assertedRole),
		profile:   profile,
		opTimeout: defaultOpTimeout,
		readers:   make(map[uint8]*sunspec.Reader),
		latest:    make(map[uint8]Snapshot),
	}
	if err := c.dial(); err != nil {
		return nil, err
	}
	return c, nil
}
