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
//
// REV0907-E7 adds the other half: now that Close's error is real, Complete
// must not simply forward it as its own return error. A cipher-suite
// procedure's criterion is decided by the handshake and the Model 1 read, both
// already complete by the time Close runs, so a teardown failure discovered
// afterwards belongs on the Report (CloseErr), not in the error that would
// turn a successful probe into a reported failure. The tests below exercise
// finishSession, the helper Complete calls after Dial and ReadModel1 succeed.
import (
	"context"
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

// TestFinishSessionRecordsCloseErrorOnTheReportNotAsAnError is REV0907-E7's
// fix to Complete (via its extracted finishSession helper): the criterion a
// cipher-suite check states — SSM-CONF-v0.8 §2.5.1.3, "the EUT-S successfully
// establishes a secure session" — is entirely about the handshake and the
// traffic carried on it, both already decided by the time Close runs. A
// teardown failure discovered afterwards must land on the Report, not turn a
// completed probe into a returned error: finishSession has no error return at
// all, so this is a structural guarantee, and this test is what proves the
// failure is not simply dropped on the floor to get there.
func TestFinishSessionRecordsCloseErrorOnTheReportNotAsAnError(t *testing.T) {
	spec := Spec{Target: "dut.example:802"}
	s := &Session{raw: closedTCPConn(t), spec: spec}
	report := finishSession(s, spec)
	if report == nil {
		t.Fatal("finishSession returned a nil report")
	}
	if report.CloseErr == "" {
		t.Fatal("Close failed (an already-closed raw connection) but Report.CloseErr is empty; " +
			"the close failure was dropped instead of recorded")
	}
	if !strings.Contains(report.CloseErr, "close raw connection") {
		t.Errorf("Report.CloseErr %q does not name the raw-connection close, so a caller cannot tell "+
			"which handle failed", report.CloseErr)
	}
}

// TestFinishSessionLeavesCloseErrEmptyOnACleanClose is the control for the
// test above: a session whose Close succeeds must report no CloseErr at all,
// so a reader can tell "teardown was clean" from "teardown was never checked"
// apart from an always-populated field that would mean nothing.
func TestFinishSessionLeavesCloseErrEmptyOnACleanClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	spec := Spec{Target: ln.Addr().String()}
	s := &Session{raw: conn, spec: spec}
	report := finishSession(s, spec)
	if report.CloseErr != "" {
		t.Errorf("a clean Close produced Report.CloseErr = %q, want empty", report.CloseErr)
	}
}

// TestCompleteSurvivesACloseFailureAfterARealHandshake is the end-to-end
// proof, against a real loopback mbaps server: a session that genuinely
// established a session AND carried a real SunSpec Model 1 read must still be
// reported as what it was, even when the teardown that follows fails. Without
// REV0907-E7 this would turn a probe that proved exactly what CRYP-001/002
// assert into a reported failure about the bench's own fd bookkeeping.
func TestCompleteSurvivesACloseFailureAfterARealHandshake(t *testing.T) {
	dev := startDevice(t, nil)
	s, err := Dial(context.Background(), dev.spec(TLS12CCM8))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	s.ReadModel1()
	if !s.model1.OK() {
		t.Fatalf("the Model 1 read failed before the close-failure scenario could be set up: %v", s.model1.Err)
	}
	// Force the close finishSession is about to perform to fail, without
	// touching the handshake or read that already succeeded — the same
	// deterministic failure REV0907-H2's TestSessionCloseReturnsTheFileCloseError
	// uses, applied to a session that is otherwise completely real.
	if err := s.file.Close(); err != nil {
		t.Fatalf("pre-closing the dup'd fd out from under the session: %v", err)
	}
	report := finishSession(s, s.spec)
	if report == nil {
		t.Fatal("finishSession returned a nil report for a session that established and read successfully")
	}
	if !report.Model1.OK() {
		t.Fatalf("the report lost the successful Model 1 read: %v", report.Model1.Err)
	}
	if report.CloseErr == "" {
		t.Fatal("the forced close failure was not recorded on the report")
	}
	if !strings.Contains(report.CloseErr, "close dup'd socket") {
		t.Errorf("Report.CloseErr %q does not name the dup'd-fd close", report.CloseErr)
	}
}
