package mbtls

import (
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
)

// TestRoleFromDER_Taxonomy is the pinning table for the role-extraction referee
// (SunSpecTCP-29/30, design doc 01 §3.1). It mirrors the T06.1 fixture matrix:
// one happy case per mandatory + vendor role, and every documented negative.
// The manifest each fixture round-trips to (expected role string OR documented
// error) is the acceptance for T06.2(e) and T06.1.
func TestRoleFromDER_Taxonomy(t *testing.T) {
	ca := mkCA(t, "mbtls-role-test CA")

	// mint returns the DER of a leaf carrying the given role extensions.
	mint := func(cn string, exts ...pkix.Extension) []byte {
		return mkLeaf(t, cn, ca, nil, exts).der
	}

	oversize := strings.Repeat("A", 1024)

	tests := []struct {
		name     string
		der      []byte
		wantRole string
		wantErr  error // nil => expect (wantRole, nil)
	}{
		// Happy path — one per mandatory + vendor role.
		{"grid-service", mint("grid", roleExtUTF8(t, "GridServiceSunSpec")), "GridServiceSunSpec", nil},
		{"super-admin", mint("super", roleExtUTF8(t, "SuperAdministratorSunSpec")), "SuperAdministratorSunSpec", nil},
		{"net-admin", mint("netadm", roleExtUTF8(t, "NetworkAdministratorSunSpec")), "NetworkAdministratorSunSpec", nil},
		{"read-only", mint("ro", roleExtUTF8(t, "ReadOnlySunSpec")), "ReadOnlySunSpec", nil},
		{"lexavolt-read-only", mint("lv", roleExtUTF8(t, "LexaVoltReadOnly")), "LexaVoltReadOnly", nil},

		// Structural negatives — a specific documented error.
		{"no-role", mint("norole"), "", ErrNoRole},
		{"two-role", mint("tworole", roleExtUTF8(t, "GridServiceSunSpec"), roleExtUTF8(t, "ReadOnlySunSpec")), "", ErrMultipleRoles},
		{"bad-encoding", mint("badenc", roleExtPrintable(t, "GridServiceSunSpec")), "", ErrBadEncoding},

		// Structurally-valid-but-unauthorized — parsed verbatim, no error; the
		// AuthZ layer (not the parser) rejects these (design doc 01 §3.1).
		{"empty-role", mint("empty", roleExtUTF8(t, "")), "", nil},
		{"oversize-role", mint("oversize", roleExtUTF8(t, oversize)), oversize, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role, err := RoleFromDER(tc.der)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is(%v)", err, tc.wantErr)
				}
				if role != "" {
					t.Errorf("role = %q on error, want empty", role)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if role != tc.wantRole {
				t.Errorf("role = %q, want %q", role, tc.wantRole)
			}
		})
	}
}

// TestRoleFromDER_GarbageInput proves the extractor fails cleanly (a wrapped
// parse error, never a panic) on non-certificate bytes — the referee runs on
// peer-supplied DER at a trust boundary.
func TestRoleFromDER_GarbageInput(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0x30, 0x00}, []byte("not a cert at all")} {
		if _, err := RoleFromDER(in); err == nil {
			t.Errorf("RoleFromDER(%q) = nil error, want parse error", in)
		}
	}
}
