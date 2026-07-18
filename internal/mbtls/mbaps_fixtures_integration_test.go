//go:build integration

package mbtls

// mbaps_fixtures_integration_test.go proves the COMMITTED certs/mbaps/ tree
// (T06.1) is not just structurally valid PEM/ASN.1 (mbaps_fixtures_test.go)
// but genuinely interoperates over a real wolfSSL handshake: the device
// server leaf loads into an mbtls.Listener (T06.1 acceptance: "server certs
// load into an mbtls.Listener"), every happy-path role cert completes mutual
// auth against it and has its role extracted end-to-end, and the two
// TLS/chain-level negatives (wrong-ca, expired) are rejected at the
// handshake while the five role-parse-level negatives complete the
// handshake and fail only at RoleFromDER — the same design-01-§3.1 split
// handshake_integration_test.go already pins for the package's own
// runtime-minted fixtures, reproduced here against the on-disk fixtures the
// aggregator emulator (T06.4) and ssm-conformance (T06.10) will actually
// load from disk.
//
// package mbtls (not mbtls_test): shares startServer/waitAccept/
// acceptResult and TestMain (wolfSSL_Init exactly once per test binary,
// CLAUDE.md invariant) with handshake_integration_test.go in this package.

import (
	"errors"
	"path/filepath"
	"testing"
)

// mbapsClientKeyPath swaps a manifest cert path's "-cert.pem" suffix for
// "-key.pem" — the fixed naming convention cmd/gen-mbaps-certs writes.
func mbapsClientKeyPath(certRelPath string) string {
	const suffix = "-cert.pem"
	base := certRelPath[:len(certRelPath)-len(suffix)]
	return base + "-key.pem"
}

// mbapsDeviceListener stands up an mbtls.Listener using the COMMITTED device
// server leaf + its trust anchor exactly as sim/mbapsdev's default flags
// would load them (-ca certs/mbaps/dev-ca.pem -cert
// certs/mbaps/dev-server-cert.pem -key certs/mbaps/dev-server-key.pem),
// proving those on-disk files are handshake-ready, not just parseable.
func mbapsDeviceListener(t *testing.T, root string, m mbapsManifest) (addr string, results <-chan acceptResult) {
	t.Helper()
	profile := DefaultServerProfile(
		filepath.Join(root, m.Device.CA),
		filepath.Join(root, m.Device.Cert),
		filepath.Join(root, m.Device.Key),
	)
	return startServer(t, profile)
}

// TestMbapsFixtures_DeviceListener_AllRoles proves every committed happy-path
// role cert dials the committed device listener successfully and the server
// extracts the expected role — the full T06.1 tree exercised over a real
// mTLS handshake, not just parsed in isolation.
func TestMbapsFixtures_DeviceListener_AllRoles(t *testing.T) {
	root := mbapsFixtureRoot(t)
	m := loadMbapsManifest(t, root)
	addr, results := mbapsDeviceListener(t, root, m)

	for _, f := range m.Clients {
		t.Run(f.Name, func(t *testing.T) {
			clientProfile := DefaultClientProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, f.Cert),
				filepath.Join(root, mbapsClientKeyPath(f.Cert)),
			)
			cs, err := Dial(addr, clientProfile)
			if err != nil {
				t.Fatalf("Dial as %s: %v", f.Name, err)
			}
			defer cs.Close()

			ss, err := waitAccept(t, results)
			if err != nil {
				t.Fatalf("server Accept: %v", err)
			}
			defer ss.Close()

			got, err := ss.Role()
			if err != nil {
				t.Fatalf("server RoleFromDER: %v", err)
			}
			if got != f.ExpectRole {
				t.Errorf("extracted role %q, want %q", got, f.ExpectRole)
			}
		})
	}
}

// TestMbapsFixtures_NegativeHandshakes drives every committed negative
// fixture against the committed device listener and asserts the
// design-01-§3.1 split: wrong-ca and expired fail the handshake itself
// (chain_valid=false in the manifest); the five role-parse negatives
// (no-role, two-role, bad-encoding, empty-role, oversize-role) complete the
// handshake — the TLS session comes up — and fail only when the server asks
// RoleFromDER for the role.
//
// The chain_valid=false cases pin MaxTLS=TLS12 on both peers, mirroring
// TestHandshake_WrongCA_Rejected/TestHandshake_NoClientCert_Rejected in
// handshake_integration_test.go: under TLS 1.3 a rejected client cert
// surfaces post-handshake (analogous to ruling C12's no-cert case), so
// Dial/Accept themselves would report success and the rejection would only
// show up on a subsequent read — TLS 1.2 surfaces it during the handshake,
// which is what this test asserts on. This is a test-harness detail, not a
// gap in mbtls's TLS 1.3 enforcement (unchanged from the existing pattern).
func TestMbapsFixtures_NegativeHandshakes(t *testing.T) {
	root := mbapsFixtureRoot(t)
	m := loadMbapsManifest(t, root)

	for _, f := range m.Negatives {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			serverProfile := DefaultServerProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, m.Device.Cert),
				filepath.Join(root, m.Device.Key),
			)
			clientProfile := DefaultClientProfile(
				filepath.Join(root, m.Device.CA),
				filepath.Join(root, f.Cert),
				filepath.Join(root, mbapsClientKeyPath(f.Cert)),
			)
			if !f.ChainValid {
				serverProfile.MaxTLS = TLS12
				clientProfile.MaxTLS = TLS12
			}
			addr, results := startServer(t, serverProfile)
			cs, dialErr := Dial(addr, clientProfile)

			if !f.ChainValid {
				// wrong-ca / expired: the handshake itself must be rejected —
				// no Session on either side, no application bytes ever flow.
				if dialErr == nil {
					cs.Close()
					t.Fatalf("Dial with %s cert succeeded, want handshake rejection (chain_valid=false)", f.Name)
				}
				ss, aerr := waitAccept(t, results)
				if aerr == nil {
					ss.Close()
					t.Fatalf("server Accept succeeded for %s cert, want rejection", f.Name)
				}
				return
			}

			// Role-parse negatives: handshake succeeds (session up); the
			// role error surfaces only when RoleFromDER runs.
			if dialErr != nil {
				t.Fatalf("Dial with %s cert failed, want handshake success (role errors are AuthZ-layer, not handshake-layer): %v", f.Name, dialErr)
			}
			defer cs.Close()
			ss, err := waitAccept(t, results)
			if err != nil {
				t.Fatalf("server Accept: %v", err)
			}
			defer ss.Close()

			wantErr := mbapsRoleErrByName[f.ExpectRoleErr]
			role, rerr := ss.Role()
			if wantErr != nil {
				if !errors.Is(rerr, wantErr) {
					t.Errorf("RoleFromDER err = %v, want errors.Is(%v)", rerr, wantErr)
				}
				return
			}
			if rerr != nil {
				t.Fatalf("unexpected RoleFromDER error: %v", rerr)
			}
			if role != f.ExpectRole {
				t.Errorf("extracted role %q, want %q", role, f.ExpectRole)
			}
		})
	}
}
