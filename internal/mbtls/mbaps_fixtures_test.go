package mbtls

// mbaps_fixtures_test.go is the T06.1 round-trip: it loads the COMMITTED
// certs/mbaps/ tree (cmd/gen-mbaps-certs's output — a real on-disk PKI, not
// the runtime-minted throwaway fixtures testpki_test.go/role_test.go use for
// mbtls's own unit tests) and proves RoleFromDER — the real parser, not a
// stand-in — agrees with manifest.json on every fixture. This is also the
// strongest available proof that cmd/gen-mbaps-certs's locally-copied role
// OID (documented there as a deliberate copy of RoleOID, kept cgo-free —
// see that command's package doc) has not drifted from role.go's: if it
// had, every fixture below would parse as ErrNoRole (the extension
// RoleFromDER looks for would be a different OID than the one the generator
// wrote), and every case in this table would fail.
//
// package mbtls (not mbtls_test): matches the existing convention in this
// directory (role_test.go, profile_test.go, testpki_test.go,
// handshake_integration_test.go are all internal test files), and lets
// mbaps_fixtures_integration_test.go share startServer/waitAccept/
// acceptResult from handshake_integration_test.go.
//
// No build tag: this is pure parsing, no wolfSSL/cgo calls, so it runs in
// the fast lane (`make test-fast`) like role_test.go. The listener/handshake
// proof against these same fixtures is
// mbaps_fixtures_integration_test.go (`-tags=integration`).

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// mbapsFixtureRoot locates the committed certs/mbaps/ tree relative to this
// package's directory (go test's working directory is always the package
// dir). Fatal, not Skip: certs/mbaps/ is git-tracked (T06.1) — its absence
// on a checkout that includes this test means the tree was deleted or the
// checkout is broken, not an optional fixture.
func mbapsFixtureRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "certs", "mbaps")
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err != nil {
		t.Fatalf("certs/mbaps/manifest.json not found at %s: %v (run `make gen-mbaps-certs`? it should be git-tracked)", root, err)
	}
	return root
}

// mbapsFixture mirrors the JSON shape cmd/gen-mbaps-certs writes (only the
// fields this test needs).
type mbapsFixture struct {
	Name          string `json:"name"`
	Cert          string `json:"cert"`
	ExpectRole    string `json:"expect_role"`
	ExpectRoleErr string `json:"expect_role_err"`
	ChainValid    bool   `json:"chain_valid"`
}

type mbapsManifest struct {
	Device struct {
		CA   string `json:"ca"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"device"`
	Clients   []mbapsFixture `json:"clients"`
	Negatives []mbapsFixture `json:"negatives"`
}

func loadMbapsManifest(t *testing.T, root string) mbapsManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var m mbapsManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse manifest.json: %v", err)
	}
	return m
}

// mbapsLeafDER reads a PEM chain file and returns the DER of its FIRST
// block — the leaf, per the "leaf first" chain convention (TCP-51) every
// fixture in this tree follows.
func mbapsLeafDER(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s: no PEM block found", path)
	}
	return block.Bytes
}

// mbapsRoleErrByName maps the manifest's string tag to the real mbtls
// sentinel — keeps the JSON human-readable while still asserting on the
// actual error values via errors.Is (the same taxonomy role_test.go pins).
var mbapsRoleErrByName = map[string]error{
	"":                 nil,
	"ErrNoRole":        ErrNoRole,
	"ErrBadEncoding":   ErrBadEncoding,
	"ErrMultipleRoles": ErrMultipleRoles,
}

// TestMbapsFixtures_RoleFromDER round-trips every committed client + negative
// fixture through the real RoleFromDER and checks it against manifest.json's
// expected role / error (T06.1 acceptance: "the manifest round-trips").
func TestMbapsFixtures_RoleFromDER(t *testing.T) {
	root := mbapsFixtureRoot(t)
	m := loadMbapsManifest(t, root)

	all := append(append([]mbapsFixture{}, m.Clients...), m.Negatives...)
	if len(all) != 5+7 {
		t.Fatalf("manifest has %d fixtures, want 5 happy-path + 7 negative = 12", len(all))
	}

	for _, f := range all {
		t.Run(f.Name, func(t *testing.T) {
			wantErr, ok := mbapsRoleErrByName[f.ExpectRoleErr]
			if !ok {
				t.Fatalf("manifest fixture %q: unrecognised expect_role_err %q", f.Name, f.ExpectRoleErr)
			}
			der := mbapsLeafDER(t, filepath.Join(root, f.Cert))
			role, err := RoleFromDER(der)
			if wantErr != nil {
				if !errors.Is(err, wantErr) {
					t.Fatalf("RoleFromDER(%s) err = %v, want errors.Is(%v)", f.Cert, err, wantErr)
				}
				if role != "" {
					t.Errorf("RoleFromDER(%s) role = %q on error, want empty", f.Cert, role)
				}
				return
			}
			if err != nil {
				t.Fatalf("RoleFromDER(%s): unexpected error: %v", f.Cert, err)
			}
			if role != f.ExpectRole {
				t.Errorf("RoleFromDER(%s) role = %q, want %q", f.Cert, role, f.ExpectRole)
			}
		})
	}
}

// TestMbapsFixtures_DeviceCertNoRole proves the committed device server leaf
// (sim/mbapsdev's default -cert) carries NO role extension, matching
// SunSpecTCP-28 (server certs need no role) and mbapsdev/main.go's doc
// comment.
func TestMbapsFixtures_DeviceCertNoRole(t *testing.T) {
	root := mbapsFixtureRoot(t)
	m := loadMbapsManifest(t, root)
	der := mbapsLeafDER(t, filepath.Join(root, m.Device.Cert))
	if _, err := RoleFromDER(der); !errors.Is(err, ErrNoRole) {
		t.Errorf("device cert RoleFromDER err = %v, want ErrNoRole", err)
	}
}
