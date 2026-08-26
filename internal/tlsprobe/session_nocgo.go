//go:build !cgo

package tlsprobe

// session_nocgo.go is the no-cgo build of the probe: the same API, refusing to
// pretend.
//
// cmd/certify must stay buildable and useful without a TLS stack — list,
// dry-run, verify and report all work there, and the certify gate holds that
// property with `CGO_ENABLED=0 go build ./cmd/certify` (Makefile, test-certify).
// The wolfSSL client cannot exist in that build, so every entry point here
// returns ErrUnavailable, which a caller must report as a fact about the BINARY.
// A probe that could not run says nothing about the device it could not reach,
// and must never be recorded as though it had.

import (
	"context"
	"net"
)

// Session is the no-cgo placeholder. It is never constructed: Dial refuses
// first. The methods exist so a caller compiles identically in both builds.
type Session struct{}

// Dial always fails in this build. See ErrUnavailable.
func Dial(_ context.Context, _ Spec) (*Session, error) { return nil, ErrUnavailable }

// Complete always fails in this build. See ErrUnavailable.
func Complete(_ context.Context, _ Spec) (*Report, error) { return nil, ErrUnavailable }

// Conn is unreachable in this build.
func (s *Session) Conn() net.Conn { return nil }

// Negotiated is unreachable in this build.
func (s *Session) Negotiated() Negotiated { return Negotiated{} }

// ReadModel1 is unreachable in this build.
func (s *Session) ReadModel1() ModelRead { return ModelRead{} }

// Report is unreachable in this build.
func (s *Session) Report() *Report { return nil }

// Close is unreachable in this build.
func (s *Session) Close() error { return nil }

// HandshakeError exists in both builds so a caller's error handling compiles
// identically. Nothing in this build produces one.
type HandshakeError struct {
	Target    string
	Requested Suite
	Offered   []Suite
	Err       error

	Code             int
	Reason           string
	PeerRejectedByUs bool
	Diagnosis        string
}

func (e *HandshakeError) Error() string { return "tlsprobe: " + ErrUnavailable.Error() }
func (e *HandshakeError) Unwrap() error { return e.Err }

// Refused always reports false in this build: no handshake was attempted, so
// none was refused.
func Refused(_ error) (*HandshakeError, bool) { return nil, false }
