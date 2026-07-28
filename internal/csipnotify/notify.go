// Package csipnotify delivers IEEE 2030.5 Notifications over the mTLS profile
// the standard actually requires.
//
// # Why this is not in sim/gridsim
//
// A Notification is the one message of a 2030.5 conversation that the SERVER
// sends, on a connection the server dials to the client's notificationURI, and
// IEEE 2030.5 §6.7 / CSIP §5.2.1.1 P9 require that connection to be the same
// mutually-authenticated profile as every other: TLS 1.2 with
// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.
//
// sim/gridsim is pure Go on purpose — its unit tests run on any machine with no
// wolfSSL sysroot — and Go's crypto/tls does not implement that suite. So
// gridsim cannot dial a conformant notification connection, and it does not
// pretend to: it exposes a Notifier seam and REFUSES an https:// URI with the
// reason recorded in its notification log, exactly as it exposes ChainSwapper
// for the certificate-chain lever. This package is the implementation an
// embedding binary with a wolfSSL client installs through it (sim/server), the
// same shape as that binary's chainAdapter.
//
// # What it reuses, and why not a new binding
//
// internal/tlsclient is already the bench's CSIP mTLS client: it pins
// ECDHE-ECDSA-AES128-CCM-8 by default, loads the CA and the client identity
// once into a wolfSSL CTX, and — since this change — arms NSS key-log export
// before every handshake. Writing a second wolfSSL binding for the notification
// leg would have duplicated the cipher policy, the handshake sequencing and the
// key-log discipline, and the copy that drifted first would have been the one
// producing conformance evidence.
//
// # Key export, which is the point of reusing it
//
// The notification leg is the only leg of a 2030.5 conversation where the bench
// is the TLS CLIENT. A capture of it decrypts under the bench's own secrets, so
// a -tags keylog build of the embedding binary makes the server-dialled leg
// citable frame by frame — which is what lets the conformance suite assert the
// DUT's answer from the wire rather than only from the server's own record of
// it (internal/certify/suitecsip's RecoverNotificationLeg). In a build without
// the tag the export calls are no-ops and the leg is captured but unreadable,
// which the suite reports rather than works around.
//
// # One dial per Notification
//
// Deliberate, and not merely simple. Notifications are rare and bursty, so a
// pooled connection would buy nothing; and each fresh dial puts a complete
// mTLS handshake in the capture, which is what a conformance criterion about
// the notification connection's cipher and certificates would have to cite.
// A pooled connection would hide every handshake after the first.
package csipnotify

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"csip-tls-test/internal/tlsclient"
)

// ContentType is the media type a 2030.5 Notification is POSTed as.
const ContentType = "application/sep+xml"

// Config is the client identity the bench presents when it dials a DUT's
// notification listener.
//
// It is a CLIENT identity, not the simulator's server one, and the distinction
// is not cosmetic: on this leg the bench is the client and the DUT is the
// server, so the certificate the DUT will authenticate is this one. Pointing
// these at the simulator's server key would present a certificate whose
// extended key usage says serverAuth to a peer performing clientAuth, and the
// handshake failure would be reported by the suite as an undeliverable
// Notification — true, but for a reason nobody would find.
type Config struct {
	// CACertPath verifies the DUT's server certificate.
	CACertPath string
	// ClientCertPath and ClientKeyPath are the identity presented to it.
	ClientCertPath string
	ClientKeyPath  string
	// CipherList overrides the CSIP-mandated suite. Leave empty; it exists for
	// negative testing only.
	CipherList string
	// Timeout bounds one delivery — dial, handshake and the wait for the DUT's
	// status line. Zero uses DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds one Notification delivery. It is short because the
// caller is gridsim's notifyChanged, which dispatches SYNCHRONOUSLY with the
// mutation that caused it: every second spent here is a second POST
// /admin/control does not return in.
const DefaultTimeout = 5 * time.Second

// Notifier delivers a Notification to a client's notificationURI. It satisfies
// sim/gridsim's Notifier seam without importing it — the interface is one
// method, and keeping the dependency one-way is what lets gridsim stay pure Go.
type Notifier struct {
	cfg Config
}

// New builds a Notifier. It does not dial anything; a bad certificate path is
// reported on the first delivery, with the path in the message, rather than
// preventing the simulator from starting.
func New(cfg Config) *Notifier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Notifier{cfg: cfg}
}

// Notify POSTs one Notification and returns the HTTP status the client
// answered.
//
// The contract it inherits from the seam is worth restating because it inverts
// the usual one: a NON-2xx status is a successful delivery, not an error. The
// conformance suite's criteria decide whether 201 or 204 was the conformant
// answer for a given row, and a transport that folded "the DUT said 400" into
// an error would destroy the only measurement this leg exists to produce. An
// error return means the Notification never reached the DUT at all.
func (n *Notifier) Notify(ctx context.Context, uri string, body []byte) (int, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return 0, fmt.Errorf("notificationURI %q is not a URI: %w", uri, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return n.notifyTLS(ctx, u, body)
	case "http":
		// A plain listener is a legitimate bench configuration — the
		// conformance suite's own fixtures use one — and installing this
		// notifier must not break it. There is nothing for wolfSSL to do on a
		// cleartext connection, so this is the same POST gridsim's built-in
		// notifier would have made.
		return n.notifyPlain(ctx, uri, body)
	default:
		return 0, fmt.Errorf("notificationURI %q has scheme %q; IEEE 2030.5 notifications travel over "+
			"https (or http on a bench listener)", uri, u.Scheme)
	}
}

func (n *Notifier) notifyTLS(ctx context.Context, u *url.URL, body []byte) (int, error) {
	if n.cfg.ClientCertPath == "" || n.cfg.ClientKeyPath == "" || n.cfg.CACertPath == "" {
		return 0, fmt.Errorf("this notifier has no client identity configured, so it cannot dial %s: "+
			"IEEE 2030.5 requires the notification connection to be mutually authenticated, and a bench "+
			"that presented no certificate would be measuring a handshake the standard does not describe. "+
			"Supply the CA, the client certificate and its key", u.Host)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}

	timeout := n.cfg.Timeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("no time left to deliver a Notification to %s", addr)
	}

	f, err := tlsclient.NewWolfSSLFetcher(tlsclient.Config{
		ServerAddr:     addr,
		CACertPath:     n.cfg.CACertPath,
		ClientCertPath: n.cfg.ClientCertPath,
		ClientKeyPath:  n.cfg.ClientKeyPath,
		CipherList:     n.cfg.CipherList,
		DialTimeout:    timeout,
		ReadTimeout:    timeout,
	})
	if err != nil {
		return 0, fmt.Errorf("configure the notification client for %s (ca=%s cert=%s key=%s): %w",
			addr, n.cfg.CACertPath, n.cfg.ClientCertPath, n.cfg.ClientKeyPath, err)
	}
	// One CTX per delivery, freed here. See the package comment on why the
	// connection is not pooled; the CTX follows the connection so a certificate
	// swapped between deliveries takes effect on the next one.
	defer f.Free()

	resp, err := f.PostStatus(pathOf(u), body, ContentType)
	if err != nil {
		return 0, fmt.Errorf("POST %s: %w", u.Redacted(), err)
	}
	return resp.StatusCode, nil
}

func (n *Notifier) notifyPlain(ctx context.Context, uri string, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, n.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", ContentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

// pathOf is the request target: the path with its query, defaulting to "/".
// A notificationURI is chosen by the DUT and may legitimately carry one.
func pathOf(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}
