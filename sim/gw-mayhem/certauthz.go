package gwmayhem

// certauthz.go is the cert-authz family: for each negative-cert fixture it plays
// the hostile aggregator presenting that leaf and records WHERE the gateway
// rejects it. The security invariant is the spec's LAYER placement (design 01
// §3.1): a role error (role-less / two-role / malformed / empty / oversize — chain
// VALID) must be an AUTHZ-layer denial — the TLS handshake succeeds and every
// request answers exception 0x01 with the session left up — while a chain error
// (expired / wrong-CA) must be a HANDSHAKE-layer rejection with no session at all.
// diagnoseCertAuthz FAILs any fixture that lands at the wrong layer.
//
// Go-literal (not data): it drives raw negative certs through ConnectCred, which
// the aggregator's data campaign schema (role ∈ the five bench roles) cannot
// express.

import (
	"context"
	"fmt"
	"sort"

	"csip-tls-test/internal/aggregator"
	"lexa-proto/sunspec"
)

// certNegatives builds the cert-authz sweep scenario.
func certNegatives() gwScenario {
	return gwScenario{
		ID:       "authz-cert-negatives",
		Desc:     "cert-authz: role errors deny at authz (0x01, session up); chain errors fail the handshake",
		Category: "mbaps-northbound-authz",
		Source:   SourceGo,
		Security: true,
		Expected: []Verdict{VerdictPass},
		arm:      armCertNegatives,
		oracle:   "certAuthz",
	}
}

// armCertNegatives sweeps every negative fixture, connecting with its hostile leaf
// and (for a fixture whose handshake succeeds) probing whether every request is
// denied 0x01.
func armCertNegatives(ctx context.Context, w *gwWorld, ev *gwEvidence) error {
	if len(w.neg) == 0 {
		ev.SetupErr = "no negative fixtures in the PKI manifest"
		return nil
	}
	// No served unit is needed: a role error is denied 0x01 BEFORE any unit lookup
	// (TCP-32), and a chain error tears the session down on the first read whatever
	// the unit — so a fixed probe unit works for both layers.
	for _, name := range sortedNegNames(w.neg) {
		f := w.neg[name]
		co := certOutcome{Fixture: f.name, ExpectLayer: f.expectLayer, Note: f.note}
		conn, err := w.connectCred(f.certFile, f.keyFile, "")
		if err != nil {
			co.Handshake = "failed"
			co.HandshakeErr = err.Error()
			ev.Certs = append(ev.Certs, co)
			continue
		}
		co.Handshake = "ok"
		probeCertAuthz(conn, pingUnit, &co)
		conn.Close()
		ev.Certs = append(ev.Certs, co)
	}
	return nil
}

// probeCertAuthz issues a read and a write over a handshake-up hostile session and
// records whether BOTH were denied with exception 0x01 (the role collapsed to
// no-role, TCP-32).
//
// It also resolves the TLS-1.3 layer-placement subtlety: a chain-invalid cert
// (wrong-CA / expired) COMPLETES the TLS 1.3 handshake (the client Certificate is
// sent after the server Finished, so the server cannot reject during the
// handshake), and the rejection surfaces only when the peer tears the session down
// on the first application read (internal/mbtls/mbaps_fixtures note). So a first
// read that returns a TRANSPORT failure (not a protocol exception) means the TLS
// layer rejected the chain — reclassify it as a handshake-layer rejection. A first
// read that returns a protocol EXCEPTION means the session is live and carrying
// frames — the cert was accepted at TLS and denied at authz.
func probeCertAuthz(conn *aggregator.Conn, unit uint8, co *certOutcome) {
	_, readErr := conn.ReadHolding(unit, sunspec.SunSpecBase, 2)
	readCode, readIsEx := exCode(readErr)
	if readErr != nil && !readIsEx {
		co.Handshake = "failed"
		co.HandshakeErr = "TLS session rejected post-handshake (chain invalid): " + firstLine(readErr.Error())
		return
	}
	co.AuthzExCode = readCode

	wres, werr := conn.ProbeDenied(unit, sunspec.ModelDERCtlAC, matrixCtrlPoint, matrixNominalPct)
	if werr != nil {
		co.ProbeErr = "write: " + werr.Error()
		return
	}
	if wres.Wrote {
		co.Note = joinNote(co.Note, "control write was ACCEPTED — role error did NOT collapse to no-role")
	}
	co.DeniedAll = readIsEx && readCode == 0x01 && !wres.Wrote && wres.ExceptionCode == 0x01
}

// exCode reports the mbap exception code an op error carries and whether it was a
// protocol exception (vs nil / a transport failure).
func exCode(err error) (uint8, bool) {
	if ex, ok := aggregator.AsException(err); ok {
		return uint8(ex.Code), true
	}
	return 0, false
}

// sortedNegNames returns the negative-fixture names in a stable order.
func sortedNegNames(neg map[string]negFixture) []string {
	out := make([]string, 0, len(neg))
	for n := range neg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// joinNote joins two note fragments with "; ".
func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return fmt.Sprintf("%s; %s", a, b)
}
