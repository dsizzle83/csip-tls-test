package mbtls

import (
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
	n, err := wolfssl.Read(c.sess.ssl, b)
	if err != nil {
		c.mu.Lock()
		dl := c.rDL
		c.mu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return n, timeoutError{op: "read"}
		}
		return n, err
	}
	return n, nil
}

func (c *tlsConn) Write(b []byte) (int, error) {
	n, err := wolfssl.Write(c.sess.ssl, b)
	if err != nil {
		c.mu.Lock()
		dl := c.wDL
		c.mu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return n, timeoutError{op: "write"}
		}
		return n, err
	}
	return n, nil
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
