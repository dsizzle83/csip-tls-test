package mbtls

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"csip-tls-test/internal/wolfssl"
)

// tlsConn adapts a completed wolfSSL session to net.Conn so callers can feed
// the decrypted byte stream straight to lexa-proto/mbap. Read/Write go through
// wolfSSL (which encrypts/decrypts over the underlying socket fd); the address
// and lifecycle methods delegate to the raw *net.TCPConn.
//
// Deadlines: wolfSSL does blocking I/O on the dup'd socket fd (from
// TCPConn.File()), which the Go runtime poller no longer manages, so net.Conn
// deadlines cannot be honoured through the poller. Instead SetDeadline pushes
// SO_RCVTIMEO/SO_SNDTIMEO onto the socket so a blocked wolfSSL_read/write
// unblocks at the deadline; a read/write that returns after its deadline has
// passed is reported as a timeout (net.Error with Timeout()==true). This is the
// deadline mechanism the aggregator's per-op read/write windows build on
// (T06.4) — mbap.Client itself sets no deadlines, per its contract.
type tlsConn struct {
	sess *Session // owns ssl/ctx/file; Close routes here

	mu       sync.Mutex
	rDL, wDL time.Time // zero == no deadline
}

// fd is the underlying socket file descriptor wolfSSL reads/writes.
func (c *tlsConn) fd() int { return int(c.sess.file.Fd()) }

func (c *tlsConn) Read(b []byte) (int, error) {
	return c.io("read", syscall.SO_RCVTIMEO,
		func() (int, error) { return wolfssl.Read(c.sess.ssl, b) },
		func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.rDL })
}

func (c *tlsConn) Write(b []byte) (int, error) {
	return c.io("write", syscall.SO_SNDTIMEO,
		func() (int, error) { return wolfssl.Write(c.sess.ssl, b) },
		func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.wDL })
}

// io runs one wolfSSL I/O call and honours the deadline this type promises.
//
// wolfSSL_read/write return -1 for "no progress, call me again"
// (WANT_READ/WANT_WRITE) exactly as they do for a dead connection, and on this
// blocking-socket-plus-SO_RCVTIMEO design a want is the ORDINARY way a socket
// timeout — or a partially received TLS record — arrives. Handing it to the
// caller as a failure is what turned a transient into a false statement about
// the DUT: on 2026-07-27 a discovery-walk read came back in 57µs with eight
// seconds of its deadline unspent, and the run reported that the gateway had
// no SunSpec identifier at any standard base address. The gateway's correct
// answer was already in that same capture, 422µs later.
//
// So a retryable code is retried until the caller's deadline genuinely
// expires, and only then reported as a timeout — which is what the type's doc
// comment above already promised and did not deliver, having checked the
// deadline once, after the fact. SO_RCVTIMEO/SO_SNDTIMEO are re-armed to the
// REMAINING time before each retry, so the loop cannot overshoot a deadline by
// re-blocking for the full original interval.
//
// With no deadline set the socket blocks indefinitely, so a want means a
// genuine short record; retrying is correct and cannot spin, because the next
// call blocks.
func (c *tlsConn) io(op string, sockOpt int, call func() (int, error), deadline func() time.Time) (int, error) {
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
				// Re-arm to what is LEFT, not to the original interval.
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

func (c *tlsConn) Close() error         { return c.sess.Close() }
func (c *tlsConn) LocalAddr() net.Addr  { return c.sess.raw.LocalAddr() }
func (c *tlsConn) RemoteAddr() net.Addr { return c.sess.raw.RemoteAddr() }

func (c *tlsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *tlsConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rDL = t
	c.mu.Unlock()
	return setSockTimeout(c.fd(), syscall.SO_RCVTIMEO, t)
}

func (c *tlsConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wDL = t
	c.mu.Unlock()
	return setSockTimeout(c.fd(), syscall.SO_SNDTIMEO, t)
}

// setSockTimeout maps an absolute deadline to a SO_RCVTIMEO/SO_SNDTIMEO
// interval on the socket. Zero time clears the timeout (indefinite blocking); a
// deadline already in the past arms the minimum non-zero interval (1µs — a zero
// timeval means "no timeout" to the kernel) so the next syscall returns
// immediately.
func setSockTimeout(fd, opt int, t time.Time) error {
	var tv syscall.Timeval
	if t.IsZero() {
		tv = syscall.Timeval{Sec: 0, Usec: 0}
	} else {
		d := time.Until(t)
		if d < time.Microsecond {
			d = time.Microsecond
		}
		tv = syscall.NsecToTimeval(int64(d))
	}
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, opt, &tv)
}

// timeoutError is a net.Error reporting an I/O deadline expiry.
type timeoutError struct{ op string }

func (e timeoutError) Error() string { return "mbtls: " + e.op + " deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
