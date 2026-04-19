package tlsserver

import (
	"net"
	"os"
	"testing"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// testClientConfig configures a serverTestClient. Empty cert/key paths
// skip loading them entirely, which drives the negative test that
// verifies the server rejects clients without credentials.
type testClientConfig struct {
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	CipherList     string // empty → DefaultCipherList
}

// serverTestClient is a minimal wolfSSL TLS 1.2 client used by the
// server's integration tests. It is intentionally separate from the
// real tlsclient.Client because we want to be able to construct
// deliberately malformed clients (no cert, wrong CA, wrong cipher)
// that the production Client API would not allow.
type serverTestClient struct {
	ctx  unsafe.Pointer
	ssl  unsafe.Pointer
	conn net.Conn
	file *os.File
}

func dialServerTestClient(t *testing.T, addr string, cfg testClientConfig) (*serverTestClient, error) {
	t.Helper()
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}

	ctx, err := wolfssl.NewClientCtx()
	if err != nil {
		return nil, err
	}

	if err := wolfssl.SetCipherList(ctx, cfg.CipherList); err != nil {
		wolfssl.FreeCtx(ctx)
		return nil, err
	}
	if err := wolfssl.LoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		wolfssl.FreeCtx(ctx)
		return nil, err
	}
	if cfg.ClientCertPath != "" {
		if err := wolfssl.UseCertFile(ctx, cfg.ClientCertPath); err != nil {
			wolfssl.FreeCtx(ctx)
			return nil, err
		}
		if err := wolfssl.UseKeyFile(ctx, cfg.ClientKeyPath); err != nil {
			wolfssl.FreeCtx(ctx)
			return nil, err
		}
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		wolfssl.FreeCtx(ctx)
		return nil, err
	}

	tcpConn := conn.(*net.TCPConn)
	file, err := tcpConn.File()
	if err != nil {
		conn.Close()
		wolfssl.FreeCtx(ctx)
		return nil, err
	}

	ssl, err := wolfssl.NewSSL(ctx)
	if err != nil {
		file.Close()
		conn.Close()
		wolfssl.FreeCtx(ctx)
		return nil, err
	}

	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		wolfssl.FreeSSL(ssl)
		file.Close()
		conn.Close()
		wolfssl.FreeCtx(ctx)
		return nil, err
	}

	if err := wolfssl.Connect(ssl); err != nil {
		wolfssl.FreeSSL(ssl)
		file.Close()
		conn.Close()
		wolfssl.FreeCtx(ctx)
		return nil, err
	}

	return &serverTestClient{ctx: ctx, ssl: ssl, conn: conn, file: file}, nil
}

func (c *serverTestClient) Close() {
	if c.ssl != nil {
		wolfssl.Shutdown(c.ssl)
		wolfssl.FreeSSL(c.ssl)
	}
	if c.file != nil {
		c.file.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.ctx != nil {
		wolfssl.FreeCtx(c.ctx)
	}
}

func (c *serverTestClient) Cipher() string  { return wolfssl.CipherName(c.ssl) }
func (c *serverTestClient) Version() string { return wolfssl.Version(c.ssl) }

func (c *serverTestClient) Request(req string) (string, error) {
	if _, err := wolfssl.Write(c.ssl, []byte(req)); err != nil {
		return "", err
	}
	buf := make([]byte, 8192)
	n, err := wolfssl.Read(c.ssl, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
