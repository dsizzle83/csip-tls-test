package mbtls

import (
	"strings"
	"testing"

	"csip-tls-test/internal/wolfssl"
)

// TestProfileValidate covers the construction-time suite-order/version guard
// (SunSpecTCP-19/20). An out-of-order or unknown suite string is a fatal config
// error — the whole point is to catch a non-conformant profile BEFORE a socket
// opens, not to discover it from a wrong negotiated suite at runtime.
func TestProfileValidate(t *testing.T) {
	ca := "ca.pem"
	base := func(mut func(*Profile)) Profile {
		p := DefaultClientProfile(ca, "chain.pem", "key.pem")
		if mut != nil {
			mut(&p)
		}
		return p
	}

	tests := []struct {
		name    string
		p       Profile
		wantErr string // "" => expect success
	}{
		{"default-client-ok", base(nil), ""},
		{"default-server-ok", DefaultServerProfile(ca, "chain.pem", "key.pem"), ""},
		{"tls12-only-ok", base(func(p *Profile) { p.MaxTLS = TLS12 }), ""},
		{"disable-ccm8-ok", base(func(p *Profile) {
			p.Suites12 = []string{"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305"}
		}), ""},
		{"single-suite-ok", base(func(p *Profile) {
			p.Suites12 = []string{"ECDHE-ECDSA-AES128-CCM-8"}
			p.Suites13 = []string{"TLS13-AES128-CCM-SHA256"}
		}), ""},

		{"min-not-tls12", base(func(p *Profile) { p.MinTLS = TLS13 }), "MinTLS must be TLS 1.2"},
		{"unknown-suite", base(func(p *Profile) {
			p.Suites12 = []string{"ECDHE-RSA-AES256-GCM-SHA384"}
		}), "not a mandated"},
		{"out-of-order-12", base(func(p *Profile) {
			p.Suites12 = []string{"ECDHE-ECDSA-AES128-CCM-8", "ECDHE-ECDSA-AES128-GCM-SHA256"}
		}), "out of the mandated order"},
		{"out-of-order-13", base(func(p *Profile) {
			p.Suites13 = []string{"TLS13-CHACHA20-POLY1305-SHA256", "TLS13-AES128-GCM-SHA256"}
		}), "out of the mandated order"},
		{"no-12-suites", base(func(p *Profile) { p.Suites12 = nil }), "no TLS 1.2 suites"},
		{"tls13-enabled-no-13-suites", base(func(p *Profile) { p.Suites13 = nil }), "no TLS 1.3 suites"},
		{"unknown-mfl", base(func(p *Profile) { p.MFLCode = 99 }), "unknown MFL selector"},
		{"no-ca", base(func(p *Profile) { p.CAFile = "" }), "CAFile is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestWolfCipherListVersionOrdering pins ruling C11: the assembled wolfSSL
// cipher-list string MUST place every TLS 1.3 suite before the TLS 1.2 suites
// (wolfSSL 5.7.6 negotiates TLS 1.3 only when a 1.3 suite leads a mixed list),
// while preserving each version's mandated internal order (TCP-17/18).
func TestWolfCipherListVersionOrdering(t *testing.T) {
	p := DefaultClientProfile("ca.pem", "chain.pem", "key.pem")
	if err := p.Validate(); err != nil {
		t.Fatalf("default profile invalid: %v", err)
	}
	got := p.WolfCipherList()
	want := strings.Join(append(append([]string{}, Mandated13...), Mandated12...), ":")
	if got != want {
		t.Fatalf("WolfCipherList()\n got: %s\nwant: %s", got, want)
	}

	// Every 1.3 suite index must precede every 1.2 suite index.
	suites := strings.Split(got, ":")
	last13, first12 := -1, len(suites)
	for i, s := range suites {
		switch {
		case strings.HasPrefix(s, "TLS13-"):
			last13 = i
		case strings.HasPrefix(s, "ECDHE-ECDSA-"):
			if i < first12 {
				first12 = i
			}
		default:
			t.Errorf("unexpected suite %q in list", s)
		}
	}
	if last13 >= first12 {
		t.Errorf("TLS 1.3 suite at %d not before first TLS 1.2 suite at %d: %s", last13, first12, got)
	}
}

// TestWolfCipherListTLS12Only proves a TLS-1.2-capped profile emits only the
// TLS 1.2 segment (no orphan 1.3 names the context would reject).
func TestWolfCipherListTLS12Only(t *testing.T) {
	p := DefaultClientProfile("ca.pem", "chain.pem", "key.pem")
	p.MaxTLS = TLS12
	if err := p.Validate(); err != nil {
		t.Fatalf("tls12-only profile invalid: %v", err)
	}
	got := p.WolfCipherList()
	if strings.Contains(got, "TLS13-") {
		t.Errorf("TLS-1.2-capped list contains a 1.3 suite: %s", got)
	}
	if got != strings.Join(Mandated12, ":") {
		t.Errorf("got %s, want %s", got, strings.Join(Mandated12, ":"))
	}
}

// TestMFLDefaultIs512 documents the profile default so a regression that turns
// off the mandated 512-byte cap (TCP-59/60) is caught in the fast lane.
func TestMFLDefaultIs512(t *testing.T) {
	if DefaultClientProfile("ca", "c", "k").MFLCode != wolfssl.MFL512 {
		t.Fatalf("client MFL default = %d, want MFL512 (%d)",
			DefaultClientProfile("ca", "c", "k").MFLCode, wolfssl.MFL512)
	}
}
