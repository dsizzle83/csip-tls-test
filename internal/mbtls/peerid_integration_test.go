//go:build integration

package mbtls

// peerid_integration_test.go is the teeth for the server-side peer-identity
// binding (peerid.go). It drives a REAL resumption chain against a REAL mbaps
// listener and asserts three separate things:
//
//  1. the role is derivable on EVERY connection in a long chain (the invariant);
//  2. the wolfSSL session-store eviction the binding exists for actually HAPPENS,
//     and the binding is what rescues it (without this the first claim could pass
//     vacuously on a build where wolfSSL never drops the chain);
//  3. with recovery deliberately disabled — the same server, the same wolfSSL, one
//     profile flag — the loss reproduces and is reported LOUDLY as
//     ErrPeerIdentityUnavailable, never as the ErrNoRole that an authorization
//     layer would turn into a denial.
//
// (3) is the deliberately non-conformant peer this repo's teeth pattern calls for
// (cf. StartLoopbackWriteRoles): a check that can only ever pass proves nothing.
//
// chainDepth is 60 because measurements on the 5.7.6 sysroot put the eviction
// somewhere between the 6th and 44th resumption of a chain — random, because it
// depends on where random session IDs hash in wolfSSL's bounded store. 60 makes the
// loss overwhelmingly likely without making the test slow (a full run is ~0.1 s);
// the tests that DEPEND on the loss having happened skip with a reason rather than
// fail if this particular run got lucky, so a build whose wolfSSL never evicts
// reports "not exercised" instead of a false failure.

import (
	"errors"
	"testing"
)

const chainDepth = 60

// chainObs is what one connection in a resumption chain observed at the server.
type chainObs struct {
	i         int
	resumed   bool
	role      string
	roleErr   error
	recovered bool
	lost      bool
}

// runChain opens chainDepth sequential connections with the same identity to the
// same listener, each closed before the next opens, so every connection after the
// first resumes the one before it. It returns the server's view of each.
func runChain(t *testing.T, serverProfile Profile) []chainObs {
	t.Helper()
	ClearSessionCache() // start from a cold client cache: connection 0 must be a FULL handshake
	p := newPKI(t)
	sp := serverProfile
	sp.CAFile, sp.CertChainFile, sp.KeyFile = p.caFile, p.serverCert, p.serverKey
	addr, results := startServer(t, sp)

	obs := make([]chainObs, 0, chainDepth)
	for i := 0; i < chainDepth; i++ {
		c, err := Dial(addr, p.clientProfile(happyRole))
		if err != nil {
			t.Fatalf("connection %d: Dial: %v", i, err)
		}
		s, err := waitAccept(t, results)
		if err != nil {
			t.Fatalf("connection %d: server Accept: %v", i, err)
		}
		// A round trip pumps the TLS 1.3 NewSessionTicket so the client has
		// something resumable to capture on Close.
		assertRoundTrip(t, c, s)
		role, roleErr := s.Role()
		obs = append(obs, chainObs{
			i: i, resumed: s.Resumed, role: role, roleErr: roleErr,
			recovered: s.IdentityRecovered, lost: s.IdentityLost,
		})
		c.Close()
		s.Close()
	}
	if obs[0].resumed {
		t.Fatal("connection 0 reported Resumed on a cold client cache — the chain was not started from a full handshake")
	}
	return obs
}

func countResumed(obs []chainObs) (resumed, recovered, lost int) {
	for _, o := range obs {
		if o.resumed {
			resumed++
		}
		if o.recovered {
			recovered++
		}
		if o.lost {
			lost++
		}
	}
	return
}

// TestServerRole_SurvivesResumptionChain is the invariant an mbaps server owes its
// authorization layer: as long as a peer keeps resuming ITS OWN session, the server
// keeps knowing which role that peer holds. Before peerid.go this failed partway
// through — silently, and at a different depth on every run, which is what made the
// gw-mayhem hermetic gate order-dependent (4caad35).
func TestServerRole_SurvivesResumptionChain(t *testing.T) {
	obs := runChain(t, DefaultServerProfile("", "", ""))
	for _, o := range obs {
		if o.roleErr != nil || o.role != happyRole {
			resumed, recovered, _ := countResumed(obs)
			t.Fatalf("connection %d (resumed=%t): role = %q, err = %v; want %q. "+
				"chain so far: %d resumed, %d recovered from the binding",
				o.i, o.resumed, o.role, o.roleErr, happyRole, resumed, recovered)
		}
		if o.lost {
			t.Fatalf("connection %d reported IdentityLost while still deriving a role", o.i)
		}
	}
	resumed, recovered, _ := countResumed(obs)
	t.Logf("%d/%d connections resumed; %d needed the identity binding to keep their role",
		resumed, len(obs), recovered)
}

// TestServerRole_ResumptionLossIsRecovered proves the previous test is not vacuous:
// wolfSSL really does stop handing back the peer certificate partway through a
// resumption chain, and the binding really is what carries the role past that
// point. If a run gets through the whole chain without wolfSSL dropping anything,
// the recovery path was not exercised and the test says so rather than claiming a
// pass it did not earn.
func TestServerRole_ResumptionLossIsRecovered(t *testing.T) {
	obs := runChain(t, DefaultServerProfile("", "", ""))
	_, recovered, lost := countResumed(obs)
	if lost != 0 {
		t.Fatalf("%d connection(s) lost the peer identity even with recovery enabled", lost)
	}
	if recovered == 0 {
		t.Skipf("wolfSSL retained the peer chain for all %d resumptions in this run — "+
			"the eviction the binding exists for did not reproduce, so the recovery path was not exercised",
			chainDepth)
	}
	// Every recovered connection must be a RESUMED one: an identity is never
	// restored onto a connection that presented its own certificate.
	for _, o := range obs {
		if o.recovered && !o.resumed {
			t.Errorf("connection %d recovered an identity without resuming — recovery must be resumption-only", o.i)
		}
		if o.recovered && o.role != happyRole {
			t.Errorf("connection %d recovered the wrong identity: role %q", o.i, o.role)
		}
	}
	t.Logf("wolfSSL dropped the peer chain partway through; %d/%d connections kept their role via the binding",
		recovered, chainDepth)
}

// TestServerRole_UnrecoverableIdentityIsLoudNotSilent is the deliberately
// non-conformant peer: the same server with recovery switched off, which
// reproduces exactly the pre-fix behaviour. The point is not that the role is lost
// — it is that losing it is REPORTED as losing it. A server that answered ErrNoRole
// here would be telling its authorization layer "this peer's certificate carries no
// role", which is a statement about a certificate it does not have.
func TestServerRole_UnrecoverableIdentityIsLoudNotSilent(t *testing.T) {
	sp := DefaultServerProfile("", "", "")
	sp.DisablePeerIdentityRecovery = true
	obs := runChain(t, sp)

	_, recovered, lost := countResumed(obs)
	if recovered != 0 {
		t.Fatalf("%d connection(s) recovered an identity with recovery disabled", recovered)
	}
	if lost == 0 {
		t.Skipf("wolfSSL retained the peer chain for all %d resumptions in this run — "+
			"the loss did not reproduce, so the loud-failure path was not exercised", chainDepth)
	}
	for _, o := range obs {
		if !o.lost {
			continue
		}
		if !o.resumed {
			t.Errorf("connection %d lost its identity on a FULL handshake — that is a different bug", o.i)
		}
		if !errors.Is(o.roleErr, ErrPeerIdentityUnavailable) {
			t.Errorf("connection %d: Role() err = %v; want ErrPeerIdentityUnavailable "+
				"(an identity that could not be established must not be reported as a certificate without a role)", o.i, o.roleErr)
		}
		if errors.Is(o.roleErr, ErrNoRole) {
			t.Errorf("connection %d reported ErrNoRole for an unestablished identity — "+
				"an authz layer would turn that into a denial it never computed", o.i)
		}
	}
	t.Logf("recovery off: %d/%d connections lost the peer identity, every one of them loudly", lost, chainDepth)
}
