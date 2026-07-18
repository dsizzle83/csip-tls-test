package main

// checks_test.go covers the pure-Go decision logic behind the checks (no TLS
// handshake): the suite/PRF predicates the cipher rows assert with, the loopback
// authz decision maps, and the minted-PKI fixture matrix — including that the
// negative certs provoke exactly the RoleFromDER error taxonomy the §5.3 checks
// key off. Runs in the fast lane (`make test-fast`).

import (
	"testing"

	"csip-tls-test/internal/aggregator"
	"csip-tls-test/internal/mbtls"
)

func TestSuitePredicates(t *testing.T) {
	// Every mandated TLS 1.2 suite is an encrypting AEAD suite with a SHA-256 PRF.
	for _, s := range mbtls.Mandated12 {
		if !isEncryptingSuite(s) {
			t.Errorf("mandated 1.2 suite %q not classified as encrypting", s)
		}
		if !isSHA256PRFSuite(s) {
			t.Errorf("mandated 1.2 suite %q not classified as SHA-256 PRF", s)
		}
	}
	all := append(append([]string{}, mbtls.Mandated12...), mbtls.Mandated13...)
	if anyContains(all, "MD5") || anyContains(all, "SHA1") || anyContains(all, "NULL") {
		t.Error("mandated suite set contains a forbidden MAC token (MD5/SHA1/NULL)")
	}
	if !allSHA256(all) {
		t.Error("not every mandated suite maps to a SHA-256 basis")
	}
	if !equalSeq(mbtls.Mandated12, mbtls.Mandated12) || equalSeq(mbtls.Mandated12, mbtls.Mandated13) {
		t.Error("equalSeq mis-compares the mandated suite orders")
	}
}

func TestPortOf(t *testing.T) {
	cases := map[string]int{"69.0.0.2:802": 802, "127.0.0.1:0": 0, "bad": 0, "host:notaport": 0}
	for in, want := range cases {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestLoopbackAuthzDecision pins the loopback authz maps that make the §5.3 checks
// meaningful: exactly the five known roles are recognized; only the write-capable
// roles may write; read-only + role-less certs may not.
func TestLoopbackAuthzDecision(t *testing.T) {
	write := roleSet([]Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin})
	for _, r := range aggregator.Roles() {
		if !recognizedRoles[string(r)] {
			t.Errorf("role %q not recognized by the loopback", r)
		}
	}
	if recognizedRoles[""] || recognizedRoles["Bogus"] {
		t.Error("empty / unknown role should not be recognized")
	}
	for _, r := range []Role{RoleGridService, RoleSuperAdmin, RoleNetworkAdmin} {
		if !write[string(r)] {
			t.Errorf("role %q should be write-capable", r)
		}
	}
	for _, r := range []Role{RoleReadOnly, RoleLexaVolt} {
		if write[string(r)] {
			t.Errorf("read-only role %q should not be write-capable", r)
		}
	}
	units := boolSet([]uint8{1, 2})
	if !units[1] || !units[2] || units[3] {
		t.Error("boolSet mapped the served units wrong")
	}
}

// TestMintLoopbackPKI proves the minted fixture matrix: every role has a
// role-bearing P-256 full-chain leaf, and each negative provokes exactly the
// RoleFromDER error the §5.3 checks assert on (the two-role/bad-encoding fixtures
// must survive crypto/x509's duplicate-extension rejection via the raw-DER path).
func TestMintLoopbackPKI(t *testing.T) {
	ps, err := mintLoopbackPKI()
	if err != nil {
		t.Fatalf("mintLoopbackPKI: %v", err)
	}
	defer ps.cleanup()

	for _, role := range aggregator.Roles() {
		c, ok := ps.roles[role]
		if !ok {
			t.Fatalf("no minted cred for role %s", role)
		}
		der, err := rawLeafDER(c.certFile)
		if err != nil {
			t.Fatalf("read %s leaf: %v", role, err)
		}
		got, err := mbtls.RoleFromDER(der)
		if err != nil || got != string(role) {
			t.Errorf("role %s: RoleFromDER = %q, err=%v; want %q", role, got, err, role)
		}
		if leaf, _ := leafOf(c.certFile); !isP256(leaf) {
			t.Errorf("role %s leaf is not P-256", role)
		}
		if d := chainDepth(c.certFile); d < 2 {
			t.Errorf("role %s chain depth %d, want ≥2 (leaf+intermediate)", role, d)
		}
	}

	wantErr := map[string]error{
		"no-role":      mbtls.ErrNoRole,
		"two-role":     mbtls.ErrMultipleRoles,
		"bad-encoding": mbtls.ErrBadEncoding,
	}
	for name, want := range wantErr {
		if !negParseErrIs(ps, name, errName(want)) {
			t.Errorf("negative %q did not provoke %v", name, want)
		}
	}
	// empty-role parses cleanly to "" (unauthorized at authz, not the parser).
	if der, err := rawLeafDER(ps.negatives["empty-role"].certFile); err == nil {
		if role, perr := mbtls.RoleFromDER(der); perr != nil || role != "" {
			t.Errorf("empty-role: RoleFromDER = %q err=%v, want \"\" nil", role, perr)
		}
	}
	// The device/server leaf carries NO role (server certs need none, TCP-28).
	if der, err := rawLeafDER(ps.devServer.certFile); err == nil {
		if _, perr := mbtls.RoleFromDER(der); perr != mbtls.ErrNoRole {
			t.Errorf("device server cert role err = %v, want ErrNoRole", perr)
		}
	}
}

func errName(err error) string {
	switch err {
	case mbtls.ErrNoRole:
		return "ErrNoRole"
	case mbtls.ErrMultipleRoles:
		return "ErrMultipleRoles"
	case mbtls.ErrBadEncoding:
		return "ErrBadEncoding"
	}
	return ""
}
