//go:build cgo

package tlsprobe

// session_close_cgo_test.go proves the REV0907-H2 fix to Session.Close: a
// failure closing the dup'd fd or the raw socket is now a REAL error a caller
// can act on, not silently discarded.
//
// Before the fix, Close always returned nil regardless of what its two
// internal Close calls reported. That made the errcheck fix to Complete (this
// package's `defer s.Close()` at the top-level call site) cosmetic rather than
// real: checking a return value that can never be non-nil is the same
// evasion `_ =` is, just spelled differently. These tests force both of
// Close's internal handles to fail for a genuine reason (an already-closed
// fd/socket) and assert the failure survives to Close's own return value.
import (
	"net"
	"os"
	"strings"
	"testing"
)

// closedTCPConn returns a net.Conn that is already closed, so a second Close
// on it fails with a real "use of closed network connection" error — a
// deterministic stand-in for the dial-time raw socket Session.raw normally
// holds.
func closedTCPConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("pre-closing the raw conn: %v", err)
	}
	return conn
}

// closedTempFile returns an *os.File that is already closed, so a second
// Close on it fails with a real fs.ErrClosed — a deterministic stand-in for
// the dup'd fd Session.file normally holds.
func closedTempFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "session-close-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("pre-closing the temp file: %v", err)
	}
	return f
}

// TestSessionCloseReturnsTheRawCloseError is the mechanism REV0907-H2 fixes:
// a raw-socket close failure must reach Close's own return value.
func TestSessionCloseReturnsTheRawCloseError(t *testing.T) {
	s := &Session{raw: closedTCPConn(t)}
	err := s.Close()
	if err == nil {
		t.Fatal("Close returned nil for an already-closed raw connection; the underlying close error was dropped")
	}
	if !strings.Contains(err.Error(), "close raw connection") {
		t.Errorf("Close's error %q does not name the raw-connection close, so a caller cannot tell which handle failed", err)
	}
}

// TestSessionCloseReturnsTheFileCloseError is the same mechanism for the
// dup'd fd Session holds alongside the raw socket.
func TestSessionCloseReturnsTheFileCloseError(t *testing.T) {
	s := &Session{file: closedTempFile(t)}
	err := s.Close()
	if err == nil {
		t.Fatal("Close returned nil for an already-closed dup'd fd; the underlying close error was dropped")
	}
	if !strings.Contains(err.Error(), "close dup'd socket") {
		t.Errorf("Close's error %q does not name the dup'd-fd close, so a caller cannot tell which handle failed", err)
	}
}

// TestSessionCloseFileErrorTakesPriorityOverRawError pins the ordering
// Close's own doc comment promises (fd before socket): with both handles
// already failing, the fd's error is the one that must surface.
func TestSessionCloseFileErrorTakesPriorityOverRawError(t *testing.T) {
	s := &Session{raw: closedTCPConn(t), file: closedTempFile(t)}
	err := s.Close()
	if err == nil {
		t.Fatal("Close returned nil with both handles already closed")
	}
	if !strings.Contains(err.Error(), "close dup'd socket") {
		t.Errorf("Close reported %q; want the file-close error, checked first", err)
	}
}
