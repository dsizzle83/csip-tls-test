//go:build cgo

package tlsprobe

// conn_cgo.go adapts a completed wolfSSL session to net.Conn so the decrypted
// stream can be fed to lexa-proto/mbap.
//
// # Deadlines, and the retry that is not optional
//
// wolfSSL does blocking I/O on the dup'd socket fd, which the Go runtime's
// poller no longer manages, so net.Conn deadlines cannot be honoured through
// it. SetDeadline instead pushes SO_RCVTIMEO/SO_SNDTIMEO onto the socket, so a
// blocked wolfSSL_read unblocks when the deadline expires.
//
// That makes a "want read" the ORDINARY way both a socket timeout and a
// partially received TLS record arrive, and handing either to the caller as a
// failure turns a transient into a false statement about the DUT. The bench has
// paid for that once already: on 2026-07-27 a discovery read came back in 57µs
// with eight seconds of its deadline unspent, and the run reported that the
// gateway had no SunSpec identifier at any standard base address — the
// gateway's correct answer was in the same capture 422µs later
// (internal/mbtls/conn.go carries the same finding and the same loop).
//
// So a retryable code is retried until the CALLER'S deadline genuinely expires,
// with the socket timeout re-armed to what is LEFT before each retry, so the
// loop cannot overshoot by re-blocking for the full original interval.

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"csip-tls-test/internal/wolfssl"
)

// probeConn is the decrypted stream of one probe session.
type probeConn struct {
	sess *Session

	mu       sync.Mutex
	rDL, wDL time.Time // zero == no deadline
}

func (c *probeConn) fd() int { return int(c.sess.file.Fd()) }

func (c *probeConn) Read(b []byte) (int, error) {
	return c.io("read", syscall.SO_RCVTIMEO,
		func() (int, error) { return wolfssl.Read(c.sess.ssl, b) },
		func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.rDL })
}

func (c *probeConn) Write(b []byte) (int, error) {
	return c.io("write", syscall.SO_SNDTIMEO,
		func() (int, error) { return wolfssl.Write(c.sess.ssl, b) },
		func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.wDL })
}

func (c *probeConn) io(op string, sockOpt int, call func() (int, error), deadline func() time.Time) (int, error) {
	for {
		n, err := call()
		if err == nil {
			return n, nil
		}
		dl := deadline()
		expired := !dl.IsZero() && !time.Now().Before(dl)

		var ioe *wolfssl.IOError
		if !expired && errors.As(err, &ioe) && ioe.Retryable() {
			if !dl.IsZero() {
				if serr := setSockTimeout(c.fd(), sockOpt, dl); serr != nil {
					return n, serr
				}
			}
			continue
		}
		if expired {
			return n, timeoutError{op: op}
		}
		return n, err
	}
}

func (c *probeConn) Close() error         { return c.sess.Close() }
func (c *probeConn) LocalAddr() net.Addr  { return c.sess.raw.LocalAddr() }
func (c *probeConn) RemoteAddr() net.Addr { return c.sess.raw.RemoteAddr() }

func (c *probeConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *probeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rDL = t
	c.mu.Unlock()
	return setSockTimeout(c.fd(), syscall.SO_RCVTIMEO, t)
}

func (c *probeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wDL = t
	c.mu.Unlock()
	return setSockTimeout(c.fd(), syscall.SO_SNDTIMEO, t)
}

// timeoutError is a net.Error reporting an I/O deadline expiry, so a caller can
// tell "the DUT said nothing in time" from "the DUT said something wrong".
type timeoutError struct{ op string }

func (e timeoutError) Error() string { return "tlsprobe: " + e.op + " deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
