// Package tlsclient implements an IEEE 2030.5 / CSIP DER client over
// mTLS via wolfSSL. It is the package under active development — the
// server package exists primarily to validate this client.
package tlsclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"

	"csip-tls-test/internal/wolfssl"
)

// Client is a CSIP-compliant mTLS client. It owns a wolfSSL context
// and, after Dial, a connected SSL session.
//
// Lifecycle: New → Dial → Get... → Close.
//
// Why split New and Dial: New does the cert loading and cipher
// configuration once. Dial establishes a TCP connection and TLS
// session. In future milestones we may want to reuse the same Client
// across multiple Dials (e.g., reconnect after a server restart),
// which is why the ctx and the per-connection state are separated.
type Client struct {
	cfg Config
	ctx unsafe.Pointer

	// Per-connection state, populated by Dial, cleared by Close.
	ssl  unsafe.Pointer
	conn net.Conn
	file *os.File
}

// New constructs a Client and configures its wolfSSL context with the
// CA, client cert, and client key. Does not open a network connection;
// call Dial for that.
func New(cfg Config) (*Client, error) {
	if cfg.CipherList == "" {
		cfg.CipherList = DefaultCipherList
	}

	ctx, err := wolfssl.NewClientCtx()
	if err != nil {
		return nil, err
	}

	ok := false
	defer func() {
		if !ok {
			wolfssl.FreeCtx(ctx)
		}
	}()

	if err := wolfssl.SetCipherList(ctx, cfg.CipherList); err != nil {
		return nil, fmt.Errorf("set cipher list: %w", err)
	}
	if err := wolfssl.LoadVerifyLocations(ctx, cfg.CACertPath); err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}
	if err := wolfssl.UseCertFile(ctx, cfg.ClientCertPath); err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	if err := wolfssl.UseKeyFile(ctx, cfg.ClientKeyPath); err != nil {
		return nil, fmt.Errorf("load client key: %w", err)
	}

	ok = true
	return &Client{cfg: cfg, ctx: ctx}, nil
}

// Dial opens a TCP connection to the configured server and performs
// the mTLS handshake. After Dial returns successfully, the Client
// holds an open TLS session ready for Get/Post requests.
//
// On error, all partially-allocated resources are released — the
// Client remains usable for a retry Dial without needing reconstruction.
func (c *Client) Dial() error {
	if c.ssl != nil {
		return errors.New("client already connected; call Close first")
	}

	conn, err := net.Dial("tcp", c.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", c.cfg.ServerAddr, err)
	}

	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return errors.New("dial returned non-TCP connection")
	}
	file, err := tcpConn.File()
	if err != nil {
		return fmt.Errorf("get file from tcp conn: %w", err)
	}
	defer func() {
		if !ok {
			file.Close()
		}
	}()

	ssl, err := wolfssl.NewSSL(c.ctx)
	if err != nil {
		return fmt.Errorf("new SSL session: %w", err)
	}
	defer func() {
		if !ok {
			wolfssl.FreeSSL(ssl)
		}
	}()

	if err := wolfssl.SetFD(ssl, int(file.Fd())); err != nil {
		return err
	}
	if err := wolfssl.Connect(ssl); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	c.ssl = ssl
	c.conn = conn
	c.file = file
	ok = true
	return nil
}

// Close shuts down the TLS session and releases the connection. After
// Close, the Client may be reused by calling Dial again. To fully
// release the wolfSSL context as well, call Free.
func (c *Client) Close() {
	if c.ssl != nil {
		wolfssl.Shutdown(c.ssl)
		wolfssl.FreeSSL(c.ssl)
		c.ssl = nil
	}
	if c.file != nil {
		c.file.Close()
		c.file = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// Free releases the wolfSSL context. Implicitly calls Close. After
// Free, the Client may not be reused. Test cleanup typically uses
// defer client.Free.
func (c *Client) Free() {
	c.Close()
	if c.ctx != nil {
		wolfssl.FreeCtx(c.ctx)
		c.ctx = nil
	}
}

// Cipher returns the negotiated cipher suite name. Only meaningful
// after a successful Dial.
func (c *Client) Cipher() string {
	if c.ssl == nil {
		return ""
	}
	return wolfssl.CipherName(c.ssl)
}

// Version returns the negotiated TLS protocol version string. Only
// meaningful after a successful Dial.
func (c *Client) Version() string {
	if c.ssl == nil {
		return ""
	}
	return wolfssl.Version(c.ssl)
}

// Post sends an HTTP POST request with body and returns the raw response.
// Same read-until-close strategy as Get. Connection is consumed by the
// round trip; call Close + Dial before reusing.
func (c *Client) Post(path string, body []byte, contentType string) ([]byte, error) {
	if c.ssl == nil {
		return nil, errors.New("client not connected; call Dial first")
	}
	req := buildPostRequest(path, c.cfg.ServerAddr, body, contentType)
	if _, err := wolfssl.Write(c.ssl, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := wolfssl.Read(c.ssl, buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
		if n < len(buf) {
			break
		}
	}
	return resp, nil
}

// Get sends a minimal HTTP GET request for the given path and returns
// the raw response (headers + body). The connection is consumed by
// the round trip because the current server sends Connection: close;
// callers should not reuse the Client without calling Close + Dial.
//
// As Milestone 3 introduces persistent connections, this will be
// updated to keep the session open across requests.
func (c *Client) Get(path string) ([]byte, error) {
	if c.ssl == nil {
		return nil, errors.New("client not connected; call Dial first")
	}

	req := buildGetRequest(path, c.cfg.ServerAddr)
	if _, err := wolfssl.Write(c.ssl, req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read until the server closes the connection or our buffer is
	// full. With Connection: close this is fine; with persistent
	// connections we'll need Content-Length parsing instead.
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := wolfssl.Read(c.ssl, buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil || n == 0 {
			break
		}
		if n < len(buf) {
			// Partial read means server has nothing more for now.
			// With Connection: close this is end-of-stream.
			break
		}
	}
	return resp, nil
}
