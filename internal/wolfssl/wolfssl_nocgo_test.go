// wolfssl_nocgo_test.go covers wolfssl_nocgo.go, the CGO_ENABLED=0 stub added
// for REV0907-E11. Without it, `CGO_ENABLED=0 go vet ./...` fails to
// typecheck internal/mbtls, internal/tlsclient and sim/tlsserver with
// "undefined: wolfssl.NewClientCtxTLS" and friends — see those packages'
// unqualified calls (e.g. internal/mbtls/client.go's wolfssl.NewClientCtxTLS)
// for why this is load-bearing rather than decorative.

//go:build !cgo

package wolfssl

import (
	"errors"
	"testing"
)

// TestNewClientCtxTLS_NoCgo asserts the constructor contract this stub
// promises: a nil handle and ErrNoCgo, never a panic or a usable pointer that
// callers would go on to dereference through cgo.
func TestNewClientCtxTLS_NoCgo(t *testing.T) {
	ctx, err := NewClientCtxTLS()
	if ctx != nil {
		t.Fatalf("NewClientCtxTLS: got non-nil ctx %v in a !cgo build", ctx)
	}
	if !errors.Is(err, ErrNoCgo) {
		t.Fatalf("NewClientCtxTLS: err = %v, want ErrNoCgo", err)
	}
}

// TestConstructors_NoCgo covers every other constructor mbtls/tlsclient/
// tlsserver call: each must return (nil, ErrNoCgo), matching
// NewClientCtxTLS's contract above.
func TestConstructors_NoCgo(t *testing.T) {
	cases := map[string]func() (interface{ Error() string }, bool){
		"NewServerCtx": func() (interface{ Error() string }, bool) {
			ctx, err := NewServerCtx()
			return err, ctx == nil
		},
		"NewClientCtx": func() (interface{ Error() string }, bool) {
			ctx, err := NewClientCtx()
			return err, ctx == nil
		},
		"NewServerCtxTLS": func() (interface{ Error() string }, bool) {
			ctx, err := NewServerCtxTLS()
			return err, ctx == nil
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			err, gotNil := run()
			if !gotNil {
				t.Fatalf("%s: returned a non-nil handle in a !cgo build", name)
			}
			if err == nil || !errors.Is(err.(error), ErrNoCgo) {
				t.Fatalf("%s: err = %v, want ErrNoCgo", name, err)
			}
		})
	}

	if ssl, err := NewSSL(nil); ssl != nil || !errors.Is(err, ErrNoCgo) {
		t.Fatalf("NewSSL: (%v, %v), want (nil, ErrNoCgo)", ssl, err)
	}
}

// TestConfigFuncs_NoCgo covers the CTX/SSL configuration calls
// internal/mbtls's client/server setup and internal/tlsclient's Dial chain
// every one unconditionally: each must report ErrNoCgo rather than silently
// succeeding against a ctx/ssl that was never real.
func TestConfigFuncs_NoCgo(t *testing.T) {
	wantErr := func(t *testing.T, name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrNoCgo) {
			t.Fatalf("%s: err = %v, want ErrNoCgo", name, err)
		}
	}
	wantErr(t, "SetCipherList", SetCipherList(nil, "ECDHE-ECDSA-AES128-CCM-8"))
	wantErr(t, "UseCertFile", UseCertFile(nil, "cert.pem"))
	wantErr(t, "UseCertChainFile", UseCertChainFile(nil, "chain.pem"))
	wantErr(t, "UseKeyFile", UseKeyFile(nil, "key.pem"))
	wantErr(t, "LoadVerifyLocations", LoadVerifyLocations(nil, "ca.pem"))
	wantErr(t, "SetFD", SetFD(nil, 0))
	wantErr(t, "Accept", Accept(nil))
	wantErr(t, "Connect", Connect(nil))
	wantErr(t, "SetMinProtoVersion", SetMinProtoVersion(nil, TLS12Version))
	wantErr(t, "SetMaxProtoVersion", SetMaxProtoVersion(nil, TLS13Version))
	wantErr(t, "UseMaxFragment", UseMaxFragment(nil, MFL512))
	wantErr(t, "UseSupportedCurve", UseSupportedCurve(nil, ECCSecp256r1))
	wantErr(t, "Rehandshake", Rehandshake(nil))
	wantErr(t, "SetNoTicketTLS12", SetNoTicketTLS12(nil))
	wantErr(t, "SetNoTicketTLS13", SetNoTicketTLS13(nil))
	wantErr(t, "SetSession", SetSession(nil, nil))
	wantErr(t, "UseSecureRenegotiation", UseSecureRenegotiation(nil))
}

// TestNoOps_NoCgo asserts the void functions (Free*, Shutdown, RequireClientCert,
// SetSessionCacheOff, Init, Cleanup) are safe, panic-free no-ops — every drop
// path in mbtls/tlsserver calls these unconditionally on nil handles.
func TestNoOps_NoCgo(t *testing.T) {
	Init()
	Cleanup()
	FreeCtx(nil)
	FreeSSL(nil)
	FreeSession(nil)
	Shutdown(nil)
	RequireClientCert(nil)
	SetSessionCacheOff(nil)
}

// TestAccessors_NoCgo asserts every read-only accessor returns its documented
// zero value rather than panicking on a nil/never-real handle.
func TestAccessors_NoCgo(t *testing.T) {
	if got := PeerCertificateDER(nil); got != nil {
		t.Errorf("PeerCertificateDER(nil) = %v, want nil", got)
	}
	if got := CipherName(nil); got != "" {
		t.Errorf("CipherName(nil) = %q, want \"\"", got)
	}
	if got := Version(nil); got != "" {
		t.Errorf("Version(nil) = %q, want \"\"", got)
	}
	if got := SessionReused(nil); got != false {
		t.Errorf("SessionReused(nil) = %v, want false", got)
	}
	if got := NegotiatedMaxFragment(nil); got != 0 {
		t.Errorf("NegotiatedMaxFragment(nil) = %v, want 0", got)
	}
	if got := GetSession(nil); got != nil {
		t.Errorf("GetSession(nil) = %v, want nil", got)
	}
	if got := PeerChainLeafDER(nil); got != nil {
		t.Errorf("PeerChainLeafDER(nil) = %v, want nil", got)
	}
	if got := SessionID(nil); got != nil {
		t.Errorf("SessionID(nil) = %v, want nil", got)
	}
}

// TestReadWrite_NoCgo covers the I/O path internal/mbtls's tlsConn and
// internal/tlsclient's Client drive directly: both must fail with ErrNoCgo,
// carrying no byte count.
func TestReadWrite_NoCgo(t *testing.T) {
	buf := make([]byte, 16)
	if n, err := Read(nil, buf); n != 0 || !errors.Is(err, ErrNoCgo) {
		t.Fatalf("Read: (%d, %v), want (0, ErrNoCgo)", n, err)
	}
	if n, err := Write(nil, buf); n != 0 || !errors.Is(err, ErrNoCgo) {
		t.Fatalf("Write: (%d, %v), want (0, ErrNoCgo)", n, err)
	}
}

// TestIOError_NoCgo asserts the *IOError contract internal/mbtls's conn.go
// depends on via errors.As: the type must exist, implement error, and its
// classification methods must not panic. Read/Write in this build never
// actually construct one (see the type's doc comment) — this test proves the
// type itself is sound so a caller's errors.As(&ioe) compiles and behaves.
func TestIOError_NoCgo(t *testing.T) {
	e := &IOError{Op: "read", Ret: -1, Code: 2}
	if e.Error() == "" {
		t.Fatal("IOError.Error() returned an empty string")
	}
	if e.Retryable() {
		t.Error("IOError.Retryable() = true in a !cgo build, want false")
	}
	if e.PeerClosed() {
		t.Error("IOError.PeerClosed() = true in a !cgo build, want false")
	}
	var target *IOError
	if errors.As(error(e), &target) == false {
		t.Fatal("errors.As failed to match *IOError against itself")
	}

	// The actual I/O path never constructs one: Read's plain ErrNoCgo must
	// NOT be mistaken for an IOError by a caller's errors.As retry check
	// (internal/mbtls/conn.go's io() loop).
	_, err := Read(nil, make([]byte, 1))
	var ioe *IOError
	if errors.As(err, &ioe) {
		t.Fatal("errors.As matched *IOError against Read's ErrNoCgo — a caller's retry loop would try to retry a build-time absence")
	}
}

// TestProfileConstants_NoCgo pins the wire-protocol constant VALUES this stub
// carries as genuine data (not stubbed — see the file-level doc comment) to
// what internal/mbtls's own const declarations
// (`TLS12 Version = wolfssl.TLS12Version`, DefaultClientProfile's MFLCode)
// require. A silently wrong value here would not fail to compile — it would
// desync the mbaps profile's Go-level constants between the cgo and !cgo
// builds without either build failing, which is exactly the kind of silent
// drift REV0907-E11 is about.
func TestProfileConstants_NoCgo(t *testing.T) {
	cases := map[string]struct{ got, want int }{
		"TLS12Version": {TLS12Version, 0x0303},
		"TLS13Version": {TLS13Version, 0x0304},
		"MFLDisabled":  {MFLDisabled, 0},
		"MFL512":       {MFL512, 1},
		"MFL1024":      {MFL1024, 2},
		"MFL2048":      {MFL2048, 3},
		"MFL4096":      {MFL4096, 4},
		"ECCSecp256r1": {ECCSecp256r1, 23},
	}
	for name, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", name, c.got, c.want)
		}
	}
}
