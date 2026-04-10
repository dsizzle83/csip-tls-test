package tlsserver

import (
	"net"
	"os"
	"testing"
	"unsafe"
)

// testClientConfig configures a testClient. Empty cert/key paths skip
// loading them entirely, which is the mechanism used by the negative
// test that verifies the server rejects clients without credentials.
type testClientConfig struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	CipherList     string // empty → DefaultCipherList
}

// testClient is a minimal wolfSSL TLS 1.2 client used by integration
// tests. It owns its own ctx, ssl, conn, and underlying file handle,
// and tears them all down in the right order on Close.
//
// We can't use crypto/tls because Go's standard library has no support
// for AES-CCM-8, so we round-trip through wolfSSL on both sides of the
// test. The fact that this works in a single test binary is enabled by
// our Init/Cleanup pattern in TestMain.
type testClient struct {
	ctx  unsafe.Pointer
	ssl  unsafe.Pointer
	conn net.Conn
	file *os.File
}

// dialTestClient performs a complete TLS handshake against addr and
// returns either a connected testClient or the error from any setup
// step. The error path tears down all partially-allocated resources.
//
// Resource cleanup on partial failure is verbose because each setup
// step needs its own unwinding. The alternative — defer-based cleanup
// with a success flag — was tried and ended up harder to read for
// this many resources. Sticking with explicit cleanup.
func dialTestClient(t *testing.T, addr string, cfg testClientConfig) (*testClient, error) {
	t.Helper()
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}

	ctx, err := newClientCtx()
	if err != nil {
		return nil, err
	}

	if err := ctxSetCipherList(ctx, cfg.CipherList); err != nil {
		ctxFree(ctx)
		return nil, err
	}
	if err := ctxLoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		ctxFree(ctx)
		return nil, err
	}
	if cfg.ClientCertPath != "" {
		if err := ctxUseCertFile(ctx, cfg.ClientCertPath); err != nil {
			ctxFree(ctx)
			return nil, err
		}
		if err := ctxUseKeyFile(ctx, cfg.ClientKeyPath); err != nil {
			ctxFree(ctx)
			return nil, err
		}
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		ctxFree(ctx)
		return nil, err
	}

	tcpConn := conn.(*net.TCPConn)
	file, err := tcpConn.File()
	if err != nil {
		conn.Close()
		ctxFree(ctx)
		return nil, err
	}

	ssl, err := newSSL(ctx)
	if err != nil {
		file.Close()
		conn.Close()
		ctxFree(ctx)
		return nil, err
	}

	if err := sslSetFD(ssl, int(file.Fd())); err != nil {
		sslFree(ssl)
		file.Close()
		conn.Close()
		ctxFree(ctx)
		return nil, err
	}

	if err := sslConnect(ssl); err != nil {
		sslFree(ssl)
		file.Close()
		conn.Close()
		ctxFree(ctx)
		return nil, err
	}

	return &testClient{
		ctx:  ctx,
		ssl:  ssl,
		conn: conn,
		file: file,
	}, nil
}

func (c *testClient) Close() {
	if c.ssl != nil {
		sslShutdown(c.ssl)
		sslFree(c.ssl)
	}
	if c.file != nil {
		c.file.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.ctx != nil {
		ctxFree(c.ctx)
	}
}

// Cipher returns the negotiated cipher suite name (e.g.,
// "ECDHE-ECDSA-AES128-CCM-8"). Only meaningful after a successful
// handshake.
func (c *testClient) Cipher() string { return sslGetCipherName(c.ssl) }

// Version returns the negotiated TLS protocol version (e.g., "TLSv1.2").
// Only meaningful after a successful handshake.
func (c *testClient) Version() string { return sslGetVersion(c.ssl) }

// Request sends an HTTP request string and returns the full response
// (headers + body). The connection is consumed by this single round
// trip because the server sends Connection: close.
func (c *testClient) Request(req string) (string, error) {
	if _, err := sslWrite(c.ssl, []byte(req)); err != nil {
		return "", err
	}
	buf := make([]byte, 8192)
	n, err := sslRead(c.ssl, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
